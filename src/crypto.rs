//! Package signing, publisher trust, sealed secrets and whole-package
//! encryption.
//!
//! No invented cryptography: Ed25519 signing keys, X25519 sealing keys and
//! AES-256-GCM payload encryption, all standard PEM-encoded.

use crate::deterministic as det;
use crate::error::BlackboxError;
use crate::storage::home;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

pub const SEAL_ALG: &str = "x25519-aesgcm-256";
const PEM_ED25519_PKCS8: &str = "302e020100300506032b657004220420";
const PEM_ED25519_SPKI: &str = "302a300506032b6570032100";
const PEM_X25519_PKCS8: &str = "302e020100300506032b656e04220420";
const PEM_X25519_SPKI: &str = "302a300506032b656e032100";

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, BlackboxError> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| BlackboxError::new("Invalid base64 in sealed payload").with_detail(e.to_string()))
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let body = b64(der);
    let mut out = format!("-----BEGIN {}-----\n", label);
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {}-----\n", label));
    out
}

fn pem_decode(pem: &str) -> Result<Vec<u8>, BlackboxError> {
    let mut bodies = Vec::new();
    for line in pem.lines() {
        // PKCS8/SPKI DER bodies are the middle lines
        if line.contains("-----") {
            continue;
        }
        bodies.push(line.trim().to_string());
    }
    b64_decode(&bodies.join(""))
}

fn ed25519_pkcs8_der(seed: &[u8]) -> Vec<u8> {
    {
        let mut der = Vec::with_capacity(PEM_ED25519_PKCS8.len() / 2 + 32);
        der.extend_from_slice(&hex::decode(PEM_ED25519_PKCS8).unwrap());
        der.extend_from_slice(seed);
        der
    }
}
fn ed25519_spki_der(pub_bytes: &[u8]) -> Vec<u8> {
    let mut der = Vec::with_capacity(PEM_ED25519_SPKI.len() / 2 + 32);
    der.extend_from_slice(&hex::decode(PEM_ED25519_SPKI).unwrap());
    der.extend_from_slice(pub_bytes);
    der
}
fn x25519_pkcs8_der(seed: &[u8]) -> Vec<u8> {
    let mut der = Vec::with_capacity(PEM_X25519_PKCS8.len() / 2 + 32);
    der.extend_from_slice(&hex::decode(PEM_X25519_PKCS8).unwrap());
    der.extend_from_slice(seed);
    der
}
fn x25519_spki_der(pub_bytes: &[u8]) -> Vec<u8> {
    let mut der = Vec::with_capacity(PEM_X25519_SPKI.len() / 2 + 32);
    der.extend_from_slice(&hex::decode(PEM_X25519_SPKI).unwrap());
    der.extend_from_slice(pub_bytes);
    der
}

pub fn keys_dir() -> PathBuf {
    let d = home().join("keys");
    let _ = std::fs::create_dir_all(&d);
    d
}

pub fn load_ed25519_private(path: &Path) -> Result<SigningKey, BlackboxError> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| BlackboxError::new("Could not read signing key.").with_detail(e.to_string()))?;
    let der = pem_decode(&pem)?;
    let seed = &der[der.len() - 32..];
    Ok(SigningKey::from_bytes(seed.try_into().unwrap()))
}

pub fn load_ed25519_public(pem: &str) -> Result<VerifyingKey, BlackboxError> {
    let der = pem_decode(pem)?;
    let pub_bytes = &der[der.len() - 32..];
    VerifyingKey::from_bytes(pub_bytes.try_into().unwrap())
        .map_err(|e| BlackboxError::new("Invalid Ed25519 public key encoding").with_detail(e.to_string()))
}

pub fn keygen(name: &str, publisher: &str) -> Result<BTreeMap<String, String>, BlackboxError> {
    let kd = keys_dir();
    let priv_path = kd.join(format!("{}.key.pem", name));
    let pub_path = kd.join(format!("{}.pub.pem", name));
    if priv_path.exists() {
        return Err(BlackboxError::new(format!("A key named '{}' already exists.", name))
            .with_detail(priv_path.display().to_string()));
    }
    let mut rng = rand::thread_rng();
    let sk = SigningKey::generate(&mut rng);
    let seed = sk.to_bytes();
    std::fs::write(&priv_path, pem_encode("PRIVATE KEY", &ed25519_pkcs8_der(&seed)))
        .map_err(|e| BlackboxError::new("Could not write signing key").with_detail(e.to_string()))?;
    std::fs::write(&pub_path, pem_encode("PUBLIC KEY", &ed25519_spki_der(&sk.verifying_key().to_bytes())))
        .map_err(|e| BlackboxError::new("Could not write public key").with_detail(e.to_string()))?;

    // sealing pair (X25519) - separate from signing on purpose
    let seal_priv: StaticSecret = StaticSecret::random_from_rng(&mut rng);
    let seal_seed: [u8; 32] = seal_priv.to_bytes();
    let seal_pub = XPublicKey::from(&seal_priv);
    let seal_key_path = kd.join(format!("{}.seal.key.pem", name));
    let seal_pub_path = kd.join(format!("{}.seal.pub.pem", name));
    std::fs::write(&seal_key_path, pem_encode("PRIVATE KEY", &x25519_pkcs8_der(&seal_seed)))
        .map_err(|e| BlackboxError::new("Could not write seal key").with_detail(e.to_string()))?;
    std::fs::write(&seal_pub_path, pem_encode("PUBLIC KEY", &x25519_spki_der(seal_pub.as_bytes())))
        .map_err(|e| BlackboxError::new("Could not write seal public key").with_detail(e.to_string()))?;

    let meta = serde_json::json!({"name": name, "publisher": publisher});
    let _ = std::fs::write(kd.join(format!("{}.meta.json", name)), serde_json::to_vec(&meta).unwrap());

    let mut out = BTreeMap::new();
    out.insert("private".into(), priv_path.display().to_string());
    out.insert("public".into(), pub_path.display().to_string());
    out.insert("seal_private".into(), seal_key_path.display().to_string());
    out.insert("seal_public".into(), seal_pub_path.display().to_string());
    out.insert("publisher".into(), publisher.to_string());
    Ok(out)
}

pub fn sign_bytes(secret: &SigningKey, msg: &[u8]) -> Vec<u8> {
    secret.sign(msg).to_bytes().to_vec()
}

pub fn public_key_pem(vk: &VerifyingKey) -> String {
    pem_encode("PUBLIC KEY", &ed25519_spki_der(&vk.to_bytes()))
}

pub fn verify_bytes(public: &VerifyingKey, sig: &[u8], msg: &[u8]) -> bool {
    let sig: ed25519_dalek::Signature = match sig.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    public.verify(msg, &sig).is_ok()
}

pub fn trust_key(pub_path: &Path, publisher: &str) -> Result<BTreeMap<String, String>, BlackboxError> {
    let pem = std::fs::read_to_string(pub_path)
        .map_err(|e| BlackboxError::new("Could not read the public key file").with_detail(e.to_string()))?;
    let vk = load_ed25519_public(&pem)?;
    let fp = det::sha256_bytes(&ed25519_spki_der(&vk.to_bytes()));
    let mut entry = BTreeMap::new();
    entry.insert("publisher".into(), publisher.to_string());
    entry.insert("sha256".into(), fp);
    let mut t = load_trust();
    t.insert(publisher.to_string(), serde_json::to_value(&entry).unwrap_or(Value::Null));
    let data = serde_json::to_string_pretty(&t).unwrap_or_default();
    let _ = std::fs::write(home().join("keys").join("trusted.json"), data);
    Ok(entry)
}

pub fn load_trust() -> BTreeMap<String, serde_json::Value> {
    let p = home().join("keys").join("trusted.json");
    if !p.exists() {
        return BTreeMap::new();
    }
    serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_default()).unwrap_or_default()
}

pub struct SignatureInfo {
    pub state: String, // unsigned | valid | trusted | invalid
    pub publisher: Option<String>,
    pub key_fingerprint: Option<String>,
    pub reason: Option<String>,
}

pub fn verify_package_signature(
    signature_json: &serde_json::Value,
    content_digest: &str,
) -> SignatureInfo {
    let sig = signature_json;
    let publisher = sig.get("publisher").and_then(|v| v.as_str()).map(|s| s.to_string());
    if sig.get("content_digest").and_then(|v| v.as_str()) != Some(content_digest) {
        return SignatureInfo {
            state: "invalid".into(),
            publisher,
            key_fingerprint: None,
            reason: Some("signature does not match package contents".into()),
        };
    }
    let pubkey_pem = match sig.get("public_key").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return SignatureInfo {
                state: "invalid".into(),
                publisher,
                key_fingerprint: None,
                reason: Some("missing public_key".into()),
            }
        }
    };
    let sig_hex = match sig.get("signature").and_then(|v| v.as_str()) {
        Some(s) => hex::decode(s).unwrap_or_default(),
        None => {
            return SignatureInfo {
                state: "invalid".into(),
                publisher,
                key_fingerprint: None,
                reason: Some("missing signature".into()),
            }
        }
    };
    let vk = match load_ed25519_public(&pubkey_pem) {
        Ok(k) => k,
        Err(e) => {
            return SignatureInfo {
                state: "invalid".into(),
                publisher,
                key_fingerprint: None,
                reason: Some(e.summary),
            }
        }
    };
    if !verify_bytes(&vk, &sig_hex, content_digest.as_bytes()) {
        return SignatureInfo {
            state: "invalid".into(),
            publisher,
            key_fingerprint: None,
            reason: Some("bad signature".into()),
        };
    }
    let key_fp = det::sha256_bytes(&ed25519_spki_der(&vk.to_bytes()));
    let trusted = load_trust();
    let publisher_name = publisher.unwrap_or_else(|| "?".to_string());
    let pinned = trusted.get(&publisher_name).and_then(|v| v.get("sha256")).and_then(|v| v.as_str()).map(|s| s.to_string());
    let state = if pinned.as_deref() == Some(key_fp.as_str()) {
        "trusted"
    } else {
        "valid"
    };
    SignatureInfo {
        state: state.into(),
        publisher: Some(publisher_name),
        key_fingerprint: Some(key_fp),
        reason: None,
    }
}

// ------------------------------------------------------------------ sealing

fn load_x25519_public_pem(data: &[u8]) -> Result<XPublicKey, BlackboxError> {
    let pem = String::from_utf8_lossy(data);
    let der = pem_decode(&pem)
        .map_err(|_| BlackboxError::new("The --to file is not a valid PEM public key."))?;
    let pub_bytes = &der[der.len() - 32..];
    Ok(XPublicKey::from(
        <[u8; 32]>::try_from(pub_bytes)
            .map_err(|_| BlackboxError::new("The --to key is not an X25519 sealing public key."
                .to_string())
                .with_try("Seal keys are the '*.seal.pub.pem' files created by 'blackbox keygen'."))?,
    ))
}

fn load_x25519_private_pem(path: &Path) -> Result<StaticSecret, BlackboxError> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| BlackboxError::new("Could not read the private seal key").with_detail(e.to_string()))?;
    let der = pem_decode(&pem)?;
    let seed = &der[der.len() - 32..];
    Ok(StaticSecret::from(<[u8; 32]>::try_from(seed).unwrap()))
}

fn ecdh_shared(ephemeral: &StaticSecret, recipient: &XPublicKey) -> [u8; 32] {
    ephemeral.diffie_hellman(recipient).to_bytes()
}

/// Encrypt payload to a recipient; returns the JSON blob for secrets.json.
pub fn seal_bytes(payload: &[u8], recipient_pub_pem: &[u8]) -> Result<Vec<u8>, BlackboxError> {
    let pubkey = load_x25519_public_pem(recipient_pub_pem)?;
    let eph = StaticSecret::random_from_rng(&mut rand::thread_rng());
    let eph_pub = XPublicKey::from(&eph);
    let shared = ecdh_shared(&eph, &pubkey);
    let cipher = Aes256Gcm::new_from_slice(&shared).unwrap();
    let mut nonce = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
    let ct = cipher
        .encrypt(
            &nonce.into(),
            Payload { msg: &payload, aad: &[] },
        )
        .map_err(|_| BlackboxError::new("AES-256-GCM encryption failed"))?;
    let blob = serde_json::json!({
        "alg": SEAL_ALG,
        "recipient": String::from_utf8_lossy(recipient_pub_pem),
        "ephemeral": b64(eph_pub.as_bytes()),
        "nonce": b64(&nonce),
        "ct": b64(&ct),
    });
    serde_json::to_vec_pretty(&det::json_sorted(&blob))
        .map_err(|e| BlackboxError::new("Could not serialize sealed blob").with_detail(e.to_string()))
}

pub fn recipient_fingerprint(recipient_pub_pem: &[u8]) -> String {
    det::sha256_bytes(recipient_pub_pem)[..16].to_string()
}

fn find_private_seal_key(recipient_pub_pem: &[u8]) -> Option<PathBuf> {
    let kd = home().join("keys");
    let want = recipient_fingerprint(recipient_pub_pem);
    let direct = kd.join(format!("{}.seal.key.pem", want));
    if direct.is_file() {
        return Some(direct);
    }
    if kd.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&kd) {
            let mut files: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().map(|e| e == "pem").unwrap_or(false)
                        && p.file_name()
                            .map(|n| n.to_string_lossy().contains(".seal.key."))
                            .unwrap_or(false)
                })
                .collect();
            files.sort();
            for p in files {
                if let Ok(sk) = load_x25519_private_pem(&p) {
                    let pubpem = pem_encode("PUBLIC KEY", &x25519_spki_der(XPublicKey::from(&sk).as_bytes()));
                    if recipient_fingerprint(pubpem.as_bytes()) == want {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

/// Decrypt a secrets.json blob using the local private seal key.
/// Returns `{key: value}`. Errors when the local key is missing.
pub fn open_sealed(blob_bytes: &[u8]) -> Result<BTreeMap<String, String>, BlackboxError> {
    let blob: serde_json::Value = serde_json::from_slice(blob_bytes).map_err(|e| {
        BlackboxError::new("Package contains a malformed sealed-secrets payload.").with_detail(e.to_string())
    })?;
    let alg = blob.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != SEAL_ALG {
        return Err(BlackboxError::new(format!("Unsupported secrets algorithm '{}'.", alg)));
    }
    let recipient_pem = blob
        .get("recipient")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    let key_path = find_private_seal_key(&recipient_pem).ok_or_else(|| {
        BlackboxError::new(
            "This package carries sealed secrets, but your machine does not hold the matching private seal key.",
        )
        .with_detail(format!("Recipient fingerprint: {}", recipient_fingerprint(&recipient_pem)))
        .with_try(format!(
            "Ask the publisher for their '*.seal.key.pem' file and place it in {}, then re-run.",
            home().join("keys").display()
        ))
    })?;
    let sk = load_x25519_private_pem(&key_path)?;
    let eph_bytes = b64_decode(blob.get("ephemeral").and_then(|v| v.as_str()).unwrap_or(""))?;
    let eph_pub = XPublicKey::from(
        <[u8; 32]>::try_from(eph_bytes.as_slice())
            .map_err(|_| BlackboxError::new("Sealed payload has an invalid ephemeral key"))?,
    );
    let shared = sk.diffie_hellman(&eph_pub).to_bytes();
    let nonce = b64_decode(blob.get("nonce").and_then(|v| v.as_str()).unwrap_or(""))?;
    let ct = b64_decode(blob.get("ct").and_then(|v| v.as_str()).unwrap_or(""))?;
    if nonce.len() != 12 {
        return Err(BlackboxError::new("Sealed payload has an invalid nonce"));
    }
    let cipher = Aes256Gcm::new_from_slice(&shared).unwrap();
    let pt = cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            Payload { msg: &ct, aad: &[] },
        )
        .map_err(|_| BlackboxError::new("Sealed secrets could not be decrypted with the local key."))?;

    let text = String::from_utf8_lossy(&pt);
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim().to_string();
            let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
            out.insert(key, val);
        }
    }
    Ok(out)
}

/// Parse KEY=VALUE lines; returns [(key, value)]. Validates names.
pub fn parse_secrets_file(path: &Path) -> Result<Vec<(String, String)>, BlackboxError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| BlackboxError::new(format!("Could not read the secrets file: {}", path.display())).with_detail(e.to_string()))?;
    let mut pairs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.contains('=') {
            return Err(BlackboxError::new(format!("Secrets line is not KEY=VALUE: '{}'", line.chars().take(40).collect::<String>())));
        }
        let (k, v) = line.split_once('=').unwrap();
        let k = k.trim();
        if !valid_env_name(k) {
            return Err(BlackboxError::new(format!("Invalid secret name '{}'.", k)));
        }
        pairs.push((k.to_string(), v.trim().trim_matches('"').trim_matches('\'').to_string()));
    }
    if pairs.is_empty() {
        return Err(BlackboxError::new("The secrets file contains no KEY=VALUE entries."));
    }
    Ok(pairs)
}

pub fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ------------------------------------------------ whole-package encryption

/// Encrypt arbitrary members to a recipient (X25519 + AES-256-GCM). Used by
/// `blackbox encrypt` and in the packaging module for sealed .blackbox files.
///
/// blob schema: {"alg": "x25519-aesgcm-256", "recipient": PEM, "ephemeral": b64,
///               "nonce": b64, "ct": b64}  (one blob per member)
pub fn seal_member_bytes(payload: &[u8], recipient_pub_pem: &[u8]) -> Result<Vec<u8>, BlackboxError> {
    seal_bytes(payload, recipient_pub_pem)
}

pub fn open_member_bytes(
    blob_json: &serde_json::Value,
) -> Result<Vec<u8>, BlackboxError> {
    let recipient_pem = blob_json
        .get("recipient")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    let key_path = find_private_seal_key(&recipient_pem).ok_or_else(|| {
        BlackboxError::new(
            "This package is sealed to a recipient, and your machine does not hold the matching private seal key.",
        )
        .with_detail(format!("Recipient fingerprint: {}", recipient_fingerprint(&recipient_pem)))
    })?;
    let sk = load_x25519_private_pem(&key_path)?;
    let eph_bytes = b64_decode(blob_json.get("ephemeral").and_then(|v| v.as_str()).unwrap_or(""))?;
    let eph_pub = XPublicKey::from(
        <[u8; 32]>::try_from(eph_bytes.as_slice())
            .map_err(|_| BlackboxError::new("Sealed member has an invalid ephemeral key"))?,
    );
    let shared = sk.diffie_hellman(&eph_pub).to_bytes();
    let nonce = b64_decode(blob_json.get("nonce").and_then(|v| v.as_str()).unwrap_or(""))?;
    let ct = b64_decode(blob_json.get("ct").and_then(|v| v.as_str()).unwrap_or(""))?;
    if nonce.len() != 12 {
        return Err(BlackboxError::new("Sealed member has an invalid nonce"));
    }
    let cipher = Aes256Gcm::new_from_slice(&shared).unwrap();
    cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            Payload { msg: &ct, aad: &[] },
        )
        .map_err(|_| BlackboxError::new("Sealed member could not be decrypted with the local key."))
}

/// Rebuild a signature over arbitrary bytes (used by self-update's signed
/// binary transport).
pub fn file_signature(secret: &SigningKey, digest: &str) -> Vec<u8> {
    sign_bytes(secret, digest.as_bytes())
}

pub fn file_verify(public_pem: &str, digest: &str, sig_hex: &str) -> bool {
    match load_ed25519_public(public_pem) {
        Ok(vk) => match hex::decode(sig_hex) {
            Ok(sig) => verify_bytes(&vk, &sig, digest.as_bytes()),
            Err(_) => false,
        },
        Err(_) => false,
    }
}
