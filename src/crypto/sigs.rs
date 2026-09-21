//! Message + file authentication and signatures.
//! - HMAC-SHA-256/384/512 for shared-secret authentication.
//! - RSA PKCS#1 v1.5 / PSS and ECDSA (P-256/P-384) file signatures.
//!
//! Verification uses constant-time comparison for HMAC and the
//! audited `rsa` / `p256` / `p384` verify paths for signatures.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

use crate::models::ToolkitError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacHash {
    Sha256,
    Sha384,
    Sha512,
}

impl HmacHash {
    pub fn label(self) -> &'static str {
        match self {
            HmacHash::Sha256 => "HMAC-SHA-256",
            HmacHash::Sha384 => "HMAC-SHA-384",
            HmacHash::Sha512 => "HMAC-SHA-512",
        }
    }
    pub fn all() -> &'static [HmacHash] {
        &[HmacHash::Sha256, HmacHash::Sha384, HmacHash::Sha512]
    }
}

pub fn hmac_bytes(hash: HmacHash, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, ToolkitError> {
    if key.is_empty() {
        return Err(ToolkitError::InvalidInput("HMAC key must not be empty".into()));
    }
    match hash {
        HmacHash::Sha256 => {
            let mut m = Hmac::<Sha256>::new_from_slice(key)
                .map_err(|_| ToolkitError::InvalidInput("bad HMAC key".into()))?;
            m.update(msg);
            Ok(m.finalize().into_bytes().to_vec())
        }
        HmacHash::Sha384 => {
            let mut m = Hmac::<Sha384>::new_from_slice(key)
                .map_err(|_| ToolkitError::InvalidInput("bad HMAC key".into()))?;
            m.update(msg);
            Ok(m.finalize().into_bytes().to_vec())
        }
        HmacHash::Sha512 => {
            let mut m = Hmac::<Sha512>::new_from_slice(key)
                .map_err(|_| ToolkitError::InvalidInput("bad HMAC key".into()))?;
            m.update(msg);
            Ok(m.finalize().into_bytes().to_vec())
        }
    }
}

pub fn hmac_verify(hash: HmacHash, key: &[u8], msg: &[u8], expected: &[u8]) -> Result<bool, ToolkitError> {
    let got = hmac_bytes(hash, key, msg)?;
    if got.len() != expected.len() {
        return Ok(false);
    }
    let mut diff = 0u8;
    for (a, b) in got.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    Ok(diff == 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigScheme {
    RsaPkcs1Sha256,
    RsaPkcs1Sha512,
    RsaPssSha256,
    RsaPssSha512,
    EcdsaP256,
    EcdsaP384,
}

impl SigScheme {
    pub fn label(self) -> &'static str {
        match self {
            SigScheme::RsaPkcs1Sha256 => "RSA PKCS#1 v1.5 + SHA-256",
            SigScheme::RsaPkcs1Sha512 => "RSA PKCS#1 v1.5 + SHA-512",
            SigScheme::RsaPssSha256 => "RSA-PSS + SHA-256",
            SigScheme::RsaPssSha512 => "RSA-PSS + SHA-512",
            SigScheme::EcdsaP256 => "ECDSA P-256",
            SigScheme::EcdsaP384 => "ECDSA P-384",
        }
    }
    pub fn all() -> &'static [SigScheme] {
        &[
            SigScheme::RsaPkcs1Sha256,
            SigScheme::RsaPkcs1Sha512,
            SigScheme::RsaPssSha256,
            SigScheme::RsaPssSha512,
            SigScheme::EcdsaP256,
            SigScheme::EcdsaP384,
        ]
    }
}

/// Sign bytes with a PEM private key. Returns raw signature bytes.
pub fn sign_bytes(scheme: SigScheme, private_pem: &str, msg: &[u8]) -> Result<Vec<u8>, ToolkitError> {
    use rsa::signature::{SignatureEncoding, Signer};
    match scheme {
        SigScheme::RsaPkcs1Sha256 => {
            let sk = crate::crypto::jwt::parse_rsa_private(private_pem)?;
            let k: rsa::pkcs1v15::SigningKey<Sha256> = rsa::pkcs1v15::SigningKey::new(sk);
            Ok(k.sign(msg).to_vec())
        }
        SigScheme::RsaPkcs1Sha512 => {
            let sk = crate::crypto::jwt::parse_rsa_private(private_pem)?;
            let k: rsa::pkcs1v15::SigningKey<Sha512> = rsa::pkcs1v15::SigningKey::new(sk);
            Ok(k.sign(msg).to_vec())
        }
        SigScheme::RsaPssSha256 => {
            let sk = crate::crypto::jwt::parse_rsa_private(private_pem)?;
            let k: rsa::pss::SigningKey<Sha256> = rsa::pss::SigningKey::new(sk);
            Ok(k.sign(msg).to_vec())
        }
        SigScheme::RsaPssSha512 => {
            let sk = crate::crypto::jwt::parse_rsa_private(private_pem)?;
            let k: rsa::pss::SigningKey<Sha512> = rsa::pss::SigningKey::new(sk);
            Ok(k.sign(msg).to_vec())
        }
        SigScheme::EcdsaP256 => {
            let key = crate::crypto::jwt::parse_p256_signing(private_pem)?;
            let sig: p256::ecdsa::Signature = key.sign(msg);
            Ok(sig.to_der().as_bytes().to_vec())
        }
        SigScheme::EcdsaP384 => {
            let key = crate::crypto::jwt::parse_p384_signing(private_pem)?;
            let sig: p384::ecdsa::Signature = key.sign(msg);
            Ok(sig.to_der().as_bytes().to_vec())
        }
    }
}

/// Verify raw signature bytes with a PEM public key (private PEM accepted).
pub fn verify_bytes(scheme: SigScheme, public_pem: &str, msg: &[u8], sig: &[u8]) -> Result<bool, ToolkitError> {
    use rsa::signature::Verifier;
    match scheme {
        SigScheme::RsaPkcs1Sha256 => {
            let pk = crate::crypto::jwt::parse_rsa_public(public_pem, Some(public_pem))?;
            let vk: rsa::pkcs1v15::VerifyingKey<Sha256> = rsa::pkcs1v15::VerifyingKey::new(pk);
            let s = rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| ToolkitError::InvalidSignature)?;
            Ok(vk.verify(msg, &s).is_ok())
        }
        SigScheme::RsaPkcs1Sha512 => {
            let pk = crate::crypto::jwt::parse_rsa_public(public_pem, Some(public_pem))?;
            let vk: rsa::pkcs1v15::VerifyingKey<Sha512> = rsa::pkcs1v15::VerifyingKey::new(pk);
            let s = rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| ToolkitError::InvalidSignature)?;
            Ok(vk.verify(msg, &s).is_ok())
        }
        SigScheme::RsaPssSha256 => {
            let pk = crate::crypto::jwt::parse_rsa_public(public_pem, Some(public_pem))?;
            let vk: rsa::pss::VerifyingKey<Sha256> = rsa::pss::VerifyingKey::new(pk);
            let s = rsa::pss::Signature::try_from(sig).map_err(|_| ToolkitError::InvalidSignature)?;
            Ok(vk.verify(msg, &s).is_ok())
        }
        SigScheme::RsaPssSha512 => {
            let pk = crate::crypto::jwt::parse_rsa_public(public_pem, Some(public_pem))?;
            let vk: rsa::pss::VerifyingKey<Sha512> = rsa::pss::VerifyingKey::new(pk);
            let s = rsa::pss::Signature::try_from(sig).map_err(|_| ToolkitError::InvalidSignature)?;
            Ok(vk.verify(msg, &s).is_ok())
        }
        SigScheme::EcdsaP256 => {
            let vk = crate::crypto::jwt::parse_p256_verifying(public_pem)?;
            let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| ToolkitError::InvalidSignature)?;
            Ok(vk.verify(msg, &s).is_ok())
        }
        SigScheme::EcdsaP384 => {
            let vk = crate::crypto::jwt::parse_p384_verifying(public_pem)?;
            let s = p384::ecdsa::Signature::from_der(sig).map_err(|_| ToolkitError::InvalidSignature)?;
            Ok(vk.verify(msg, &s).is_ok())
        }
    }
}

/// Stream a file in 64 KiB chunks through a byte-wise signer/hasher closure.
pub fn read_file_chunked(path: &str, cap_bytes: usize) -> Result<Vec<u8>, ToolkitError> {
    use std::io::Read;
    let meta = std::fs::metadata(path).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
    if meta.len() as usize > cap_bytes {
        return Err(ToolkitError::FileRead(format!("file exceeds {} MiB cap", cap_bytes / 1024 / 1024)));
    }
    let f = std::fs::File::open(path).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
    let mut r = std::io::BufReader::new(f);
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut chunk).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if out.len() > cap_bytes {
            return Err(ToolkitError::FileRead("file too large".into()));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_rfc4231_vector() {
        // RFC 4231 Test Case 1: key = 20×0x0b, data = "Hi There".
        // Cross-checked against a hand-rolled RFC 2104 construction
        // (independent of the `hmac` crate) plus the published vector.
        let key = [0x0bu8; 20];
        let mac = hmac_bytes(HmacHash::Sha256, &key, b"Hi There").unwrap();
        assert_eq!(hex::encode(&mac), manual_hmac_sha256(&key, b"Hi There"));
        assert_eq!(
            hex::encode(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// Minimal RFC 2104 HMAC-SHA-256 built directly on `sha2`.
    fn manual_hmac_sha256(key: &[u8], msg: &[u8]) -> String {
        use sha2::Digest;
        let mut kb = vec![0u8; 64];
        if key.len() > 64 {
            kb[..32].copy_from_slice(&sha2::Sha256::digest(key));
        } else {
            kb[..key.len()].copy_from_slice(key);
        }
        let ipad: Vec<u8> = kb.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = kb.iter().map(|b| b ^ 0x5c).collect();
        let mut inner = sha2::Sha256::new();
        inner.update(&ipad);
        inner.update(msg);
        let inner_hash = inner.finalize();
        let mut outer = sha2::Sha256::new();
        outer.update(&opad);
        outer.update(inner_hash);
        hex::encode(outer.finalize())
    }

    #[test]
    fn hmac_verify_roundtrip() {
        let mac = hmac_bytes(HmacHash::Sha512, b"key", b"msg").unwrap();
        assert!(hmac_verify(HmacHash::Sha512, b"key", b"msg", &mac).unwrap());
        assert!(!hmac_verify(HmacHash::Sha512, b"key", b"other", &mac).unwrap());
    }
}
