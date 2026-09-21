//! Authenticated encryption: AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305.
//!
//! Two modes:
//! - Password-based (Argon2id -> key, random salt, random nonce, JSON envelope).
//! - Raw-key (caller supplies exact-size key; random nonce per call).

use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use crate::models::{ArgonParams, CipherAlgorithm, EncryptedEnvelope, ToolkitError};

const ENVELOPE_VERSION: u8 = 1;

fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    b
}

fn derive_argon2id(password: &[u8], salt: &[u8], params: &ArgonParams, key_len: usize) -> Result<Vec<u8>, ToolkitError> {
    let p = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(key_len),
    )
    .map_err(|e| ToolkitError::Encryption(format!("bad Argon2 params: {e}")))?;
    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = vec![0u8; key_len];
    ctx.hash_password_into(password, salt, &mut out)
        .map_err(|e| ToolkitError::Encryption(format!("argon2 failed: {e}")))?;
    Ok(out)
}

fn encrypt_aead(
    alg: CipherAlgorithm,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ToolkitError> {
    if key.len() != alg.key_len() {
        return Err(ToolkitError::InvalidKeyLength {
            expected: alg.key_len(),
            actual: key.len(),
        });
    }
    if nonce.len() != alg.nonce_len() {
        return Err(ToolkitError::InvalidInput(format!(
            "nonce must be {} bytes for {}",
            alg.nonce_len(),
            alg.label()
        )));
    }
    match alg {
        CipherAlgorithm::Aes256Gcm => {
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|e| ToolkitError::Encryption(e.to_string()))?;
            c.encrypt(AesNonce::from_slice(nonce), aes_gcm::aead::Payload { msg: plaintext, aad })
                .map_err(|_| ToolkitError::DecryptionFailed)
        }
        CipherAlgorithm::Aes128Gcm => {
            let c = Aes128Gcm::new_from_slice(key)
                .map_err(|e| ToolkitError::Encryption(e.to_string()))?;
            c.encrypt(AesNonce::from_slice(nonce), aes_gcm::aead::Payload { msg: plaintext, aad })
                .map_err(|_| ToolkitError::DecryptionFailed)
        }
        CipherAlgorithm::ChaCha20Poly1305 => {
            let c = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| ToolkitError::Encryption(e.to_string()))?;
            c.encrypt(
                chacha20poly1305::Nonce::from_slice(nonce),
                chacha20poly1305::aead::Payload { msg: plaintext, aad },
            )
            .map_err(|_| ToolkitError::DecryptionFailed)
        }
        CipherAlgorithm::XChaCha20Poly1305 => {
            let c = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| ToolkitError::Encryption(e.to_string()))?;
            c.encrypt(
                chacha20poly1305::XNonce::from_slice(nonce),
                chacha20poly1305::aead::Payload { msg: plaintext, aad },
            )
            .map_err(|_| ToolkitError::DecryptionFailed)
        }
    }
}

fn decrypt_aead(
    alg: CipherAlgorithm,
    key: &[u8],
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ToolkitError> {
    if key.len() != alg.key_len() {
        return Err(ToolkitError::InvalidKeyLength {
            expected: alg.key_len(),
            actual: key.len(),
        });
    }
    if nonce.len() != alg.nonce_len() {
        return Err(ToolkitError::InvalidInput(format!(
            "nonce must be {} bytes for {}",
            alg.nonce_len(),
            alg.label()
        )));
    }
    let res = match alg {
        CipherAlgorithm::Aes256Gcm => {
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|e| ToolkitError::Encryption(e.to_string()))?;
            c.decrypt(
                AesNonce::from_slice(nonce),
                aes_gcm::aead::Payload { msg: ciphertext_and_tag, aad },
            )
        }
        CipherAlgorithm::Aes128Gcm => {
            let c = Aes128Gcm::new_from_slice(key)
                .map_err(|e| ToolkitError::Encryption(e.to_string()))?;
            c.decrypt(
                AesNonce::from_slice(nonce),
                aes_gcm::aead::Payload { msg: ciphertext_and_tag, aad },
            )
        }
        CipherAlgorithm::ChaCha20Poly1305 => {
            let c = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| ToolkitError::Encryption(e.to_string()))?;
            c.decrypt(
                chacha20poly1305::Nonce::from_slice(nonce),
                chacha20poly1305::aead::Payload { msg: ciphertext_and_tag, aad },
            )
        }
        CipherAlgorithm::XChaCha20Poly1305 => {
            let c = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| ToolkitError::Encryption(e.to_string()))?;
            c.decrypt(
                chacha20poly1305::XNonce::from_slice(nonce),
                chacha20poly1305::aead::Payload { msg: ciphertext_and_tag, aad },
            )
        }
    };
    res.map_err(|_| ToolkitError::DecryptionFailed)
}

fn parse_alg(s: &str) -> Result<CipherAlgorithm, ToolkitError> {
    match s {
        "AES-256-GCM" => Ok(CipherAlgorithm::Aes256Gcm),
        "AES-128-GCM" => Ok(CipherAlgorithm::Aes128Gcm),
        "ChaCha20-Poly1305" => Ok(CipherAlgorithm::ChaCha20Poly1305),
        "XChaCha20-Poly1305" => Ok(CipherAlgorithm::XChaCha20Poly1305),
        other => Err(ToolkitError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Password-based encryption. Returns the envelope as pretty JSON.
pub fn encrypt_with_password(
    alg: CipherAlgorithm,
    plaintext: &[u8],
    password: &str,
    aad: &[u8],
    params: &ArgonParams,
) -> Result<String, ToolkitError> {
    if password.is_empty() {
        return Err(ToolkitError::InvalidPassword);
    }
    let salt = random_bytes(16);
    let nonce = random_bytes(alg.nonce_len());
    let mut key = derive_argon2id(password.as_bytes(), &salt, params, alg.key_len())?;
    let ct = encrypt_aead(alg, &key, &nonce, plaintext, aad);
    key.zeroize();
    let ct = ct?;
    let env = EncryptedEnvelope {
        version: ENVELOPE_VERSION,
        algorithm: alg.label().to_string(),
        kdf: "Argon2id".to_string(),
        argon_m_cost_kib: params.m_cost_kib,
        argon_t_cost: params.t_cost,
        argon_p_cost: params.p_cost,
        salt_b64: B64.encode(&salt),
        nonce_b64: B64.encode(&nonce),
        aad_b64: if aad.is_empty() { None } else { Some(B64.encode(aad)) },
        ciphertext_b64: B64.encode(&ct),
    };
    serde_json::to_string_pretty(&env)
        .map_err(|e| ToolkitError::Encryption(e.to_string()))
}

/// Password-based decryption. Accepts envelope JSON.
pub fn decrypt_with_password(
    envelope_json: &str,
    password: &str,
    expected_aad: Option<&[u8]>,
) -> Result<Vec<u8>, ToolkitError> {
    if password.is_empty() {
        return Err(ToolkitError::InvalidPassword);
    }
    let env: EncryptedEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| ToolkitError::MalformedPackage(e.to_string()))?;
    if env.version != ENVELOPE_VERSION {
        return Err(ToolkitError::MalformedPackage(format!(
            "unsupported version {}",
            env.version
        )));
    }
    if env.kdf != "Argon2id" {
        return Err(ToolkitError::UnsupportedAlgorithm(env.kdf));
    }
    let alg = parse_alg(&env.algorithm)?;
    let salt = B64.decode(env.salt_b64.trim()).map_err(|_| ToolkitError::MalformedPackage("bad salt".into()))?;
    let nonce = B64.decode(env.nonce_b64.trim()).map_err(|_| ToolkitError::MalformedPackage("bad nonce".into()))?;
    let ct = B64.decode(env.ciphertext_b64.trim()).map_err(|_| ToolkitError::MalformedPackage("bad ciphertext".into()))?;
    let aad: Vec<u8> = match (&env.aad_b64, expected_aad) {
        (Some(stored), Some(provided)) => {
            let s = B64.decode(stored.trim()).map_err(|_| ToolkitError::MalformedPackage("bad aad".into()))?;
            if s != provided {
                return Err(ToolkitError::DecryptionFailed);
            }
            s
        }
        (Some(stored), None) => B64.decode(stored.trim()).map_err(|_| ToolkitError::MalformedPackage("bad aad".into()))?,
        (None, Some(provided)) => {
            if !provided.is_empty() {
                return Err(ToolkitError::DecryptionFailed);
            }
            Vec::new()
        }
        (None, None) => Vec::new(),
    };
    let params = ArgonParams {
        m_cost_kib: env.argon_m_cost_kib,
        t_cost: env.argon_t_cost,
        p_cost: env.argon_p_cost,
    };
    let mut key = derive_argon2id(password.as_bytes(), &salt, &params, alg.key_len())?;
    let pt = decrypt_aead(alg, &key, &nonce, &ct, &aad);
    key.zeroize();
    pt
}

/// Raw-key encryption. Returns Base64(nonce || ciphertext+tag).
/// A fresh random nonce is generated on every call and prepended.
pub fn encrypt_with_raw_key(
    alg: CipherAlgorithm,
    plaintext: &[u8],
    key: &[u8],
    aad: &[u8],
) -> Result<String, ToolkitError> {
    let nonce = random_bytes(alg.nonce_len());
    let ct = encrypt_aead(alg, key, &nonce, plaintext, aad)?;
    let mut out = nonce;
    out.extend_from_slice(&ct);
    Ok(B64.encode(&out))
}

/// Raw-key decryption. Expects Base64(nonce || ciphertext+tag).
pub fn decrypt_with_raw_key(
    alg: CipherAlgorithm,
    package_b64: &str,
    key: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ToolkitError> {
    let raw = B64.decode(package_b64.trim()).map_err(|_| ToolkitError::InvalidBase64)?;
    if raw.len() < alg.nonce_len() + 16 {
        return Err(ToolkitError::MalformedPackage("package too short".into()));
    }
    let (nonce, ct) = raw.split_at(alg.nonce_len());
    decrypt_aead(alg, key, nonce, ct, aad)
}

/// Parse a user-supplied raw key: hex or base64, exact length required.
pub fn parse_raw_key(input: &str, alg: CipherAlgorithm) -> Result<Vec<u8>, ToolkitError> {
    let t = input.trim();
    // Try hex first (common for keys), then base64.
    if let Ok(b) = hex::decode(t.replace([' ', '\n', '\r', '\t'], "")) {
        if b.len() == alg.key_len() {
            return Ok(b);
        }
    }
    if let Ok(b) = B64.decode(t) {
        if b.len() == alg.key_len() {
            return Ok(b);
        }
    }
    // Also accept base64 without padding / url-safe.
    if let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t) {
        if b.len() == alg.key_len() {
            return Ok(b);
        }
    }
    Err(ToolkitError::InvalidKeyLength {
        expected: alg.key_len(),
        actual: t.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn light_params() -> ArgonParams {
        ArgonParams { m_cost_kib: 8192, t_cost: 1, p_cost: 1 }
    }

    #[test]
    fn password_roundtrip_all_algs() {
        for alg in CipherAlgorithm::all() {
            let env = encrypt_with_password(*alg, b"hello world", "correct horse battery staple", b"", &light_params()).unwrap();
            let pt = decrypt_with_password(&env, "correct horse battery staple", None).unwrap();
            assert_eq!(pt, b"hello world");
        }
    }

    #[test]
    fn wrong_password_fails() {
        let env = encrypt_with_password(CipherAlgorithm::Aes256Gcm, b"secret", "right-password-1", b"", &light_params()).unwrap();
        assert!(decrypt_with_password(&env, "wrong-password-2", None).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let env = encrypt_with_password(CipherAlgorithm::ChaCha20Poly1305, b"data", "password-12345", b"", &light_params()).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&env).unwrap();
        v["ciphertext_b64"] = serde_json::Value::String(B64.encode(b"tampered-tampered-tampered!!"));
        let bad = v.to_string();
        assert!(decrypt_with_password(&bad, "password-12345", None).is_err());
    }

    #[test]
    fn raw_key_roundtrip() {
        let key = vec![7u8; 32];
        let pkg = encrypt_with_raw_key(CipherAlgorithm::Aes256Gcm, b"abc", &key, b"aad").unwrap();
        let pt = decrypt_with_raw_key(CipherAlgorithm::Aes256Gcm, &pkg, &key, b"aad").unwrap();
        assert_eq!(pt, b"abc");
        // wrong aad fails
        assert!(decrypt_with_raw_key(CipherAlgorithm::Aes256Gcm, &pkg, &key, b"other").is_err());
    }

    #[test]
    fn raw_key_rejects_bad_length() {
        assert!(encrypt_with_raw_key(CipherAlgorithm::Aes256Gcm, b"x", &[1u8; 16], b"").is_err());
    }
}
