//! JWE compact serialization, `alg=dir` + `enc=A256GCM` profile (RFC 7516/7518).
//! Direct symmetric encryption with a 256-bit content-encryption key:
//! no key wrapping, no custom crypto — AES-256-GCM via the audited crate.

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};

use crate::models::ToolkitError;

fn b64u(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn unb64u(s: &str) -> Result<Vec<u8>, ToolkitError> {
    URL_SAFE_NO_PAD.decode(s.trim()).map_err(|_| ToolkitError::InvalidBase64Url)
}

/// Parse a 256-bit raw key from hex or base64. Never truncated or padded.
pub fn parse_cek(input: &str) -> Result<Vec<u8>, ToolkitError> {
    let t: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(b) = hex::decode(&t) {
        if b.len() == 32 {
            return Ok(b);
        }
    }
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(&t) {
        if b.len() == 32 {
            return Ok(b);
        }
    }
    if let Ok(b) = URL_SAFE_NO_PAD.decode(&t) {
        if b.len() == 32 {
            return Ok(b);
        }
    }
    Err(ToolkitError::InvalidKeyLength { expected: 32, actual: t.len() })
}

pub fn random_cek_b64() -> String {
    let mut b = vec![0u8; 32];
    OsRng.fill_bytes(&mut b);
    base64::engine::general_purpose::STANDARD.encode(&b)
}

const PROTECTED: &str = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0"; // {"alg":"dir","enc":"A256GCM"}

/// Encrypt a payload into JWE compact serialization (5 parts).
pub fn encrypt_jwe(payload_json: &str, cek: &[u8], aad_b64u: Option<&str>) -> Result<String, ToolkitError> {
    if cek.len() != 32 {
        return Err(ToolkitError::InvalidKeyLength { expected: 32, actual: cek.len() });
    }
    let v: serde_json::Value = serde_json::from_str(payload_json)
        .map_err(|e| ToolkitError::InvalidJson(e.to_string()))?;
    let plaintext = v.to_string();
    let mut iv = vec![0u8; 12];
    OsRng.fill_bytes(&mut iv);
    // AAD = ASCII(protected) [+ "." + ASCII(aad)].
    let mut aad = PROTECTED.as_bytes().to_vec();
    if let Some(extra) = aad_b64u {
        if extra.trim().is_empty() {
            return Err(ToolkitError::InvalidInput("external AAD must not be empty".into()));
        }
        // Validate it is base64url.
        unb64u(extra)?;
        aad.push(b'.');
        aad.extend_from_slice(extra.trim().as_bytes());
    }
    let cipher = Aes256Gcm::new_from_slice(cek).map_err(|e| ToolkitError::Encryption(e.to_string()))?;
    let ct_and_tag = cipher
        .encrypt(Nonce::from_slice(&iv), aes_gcm::aead::Payload { msg: plaintext.as_bytes(), aad: &aad })
        .map_err(|_| ToolkitError::Encryption("AES-GCM encryption failed".into()))?;
    // Split tag (last 16 bytes) per JWE layout.
    if ct_and_tag.len() < 16 {
        return Err(ToolkitError::Encryption("ciphertext too short".into()));
    }
    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);
    // Compact JWE: protected . encrypted-key(empty for dir) . iv . ciphertext . tag.
    // External AAD (if any) was bound into the AEAD above and travels out-of-band.
    Ok(format!("{}.{}.{}.{}.{}", PROTECTED, "", b64u(&iv), b64u(ct), b64u(tag)))
}

/// Decrypt JWE compact serialization with the raw CEK.
pub fn decrypt_jwe(compact: &str, cek: &[u8], external_aad_b64u: Option<&str>) -> Result<String, ToolkitError> {
    if cek.len() != 32 {
        return Err(ToolkitError::InvalidKeyLength { expected: 32, actual: cek.len() });
    }
    let parts: Vec<&str> = compact.trim().split('.').collect();
    if parts.len() != 5 {
        return Err(ToolkitError::InvalidJwtFormat);
    }
    if parts[0] != PROTECTED {
        return Err(ToolkitError::UnsupportedAlgorithm("only alg=dir enc=A256GCM is supported".into()));
    }
    if !parts[1].is_empty() {
        return Err(ToolkitError::MalformedPackage("dir alg requires empty encrypted-key segment".into()));
    }
    let iv = unb64u(parts[2])?;
    let ct = unb64u(parts[3])?;
    let tag = unb64u(parts[4])?;
    if iv.len() != 12 || tag.len() != 16 {
        return Err(ToolkitError::MalformedPackage("bad iv or tag length".into()));
    }
    if let Some(extra) = external_aad_b64u {
        unb64u(extra)?;
    }
    let mut aad = PROTECTED.as_bytes().to_vec();
    if let Some(extra) = external_aad_b64u {
        if !extra.trim().is_empty() {
            aad.push(b'.');
            aad.extend_from_slice(extra.trim().as_bytes());
        }
    }
    let mut ct_and_tag = ct;
    ct_and_tag.extend_from_slice(&tag);
    let cipher = Aes256Gcm::new_from_slice(cek).map_err(|e| ToolkitError::Encryption(e.to_string()))?;
    let pt = cipher
        .decrypt(Nonce::from_slice(&iv), aes_gcm::aead::Payload { msg: &ct_and_tag, aad: &aad })
        .map_err(|_| ToolkitError::DecryptionFailed)?;
    let s = String::from_utf8(pt).map_err(|_| ToolkitError::DecryptionFailed)?;
    // Re-pretty for display; error if not JSON.
    let v: serde_json::Value = serde_json::from_str(&s).map_err(|_| ToolkitError::DecryptionFailed)?;
    serde_json::to_string_pretty(&v).map_err(|e| ToolkitError::InvalidJson(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let cek = parse_cek(&random_cek_b64()).unwrap();
        let c = encrypt_jwe(r#"{"sub":"123","role":"USER"}"#, &cek, None).unwrap();
        assert_eq!(c.split('.').count(), 5);
        let p = decrypt_jwe(&c, &cek, None).unwrap();
        assert!(p.contains("USER"));
    }

    #[test]
    fn wrong_key_fails() {
        let cek = parse_cek(&random_cek_b64()).unwrap();
        let other = parse_cek(&random_cek_b64()).unwrap();
        let c = encrypt_jwe(r#"{"a":1}"#, &cek, None).unwrap();
        assert!(decrypt_jwe(&c, &other, None).is_err());
    }

    #[test]
    fn tampered_tag_fails() {
        let cek = parse_cek(&random_cek_b64()).unwrap();
        let c = encrypt_jwe(r#"{"a":1}"#, &cek, None).unwrap();
        let mut parts: Vec<String> = c.split('.').map(|s| s.to_string()).collect();
        parts[4] = b64u(b"tampered-tampered!?");
        assert!(decrypt_jwe(&parts.join("."), &cek, None).is_err());
    }
}
