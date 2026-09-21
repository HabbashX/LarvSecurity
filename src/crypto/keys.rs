//! Key generation: symmetric bytes, RSA, EC (P-256/P-384/P-521).
//!
//! Private key material is returned as PEM strings; callers must treat
//! them as sensitive (no logging, clear on navigation).

use base64::engine;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use crate::models::ToolkitError;

pub fn generate_symmetric_hex(num_bytes: usize) -> Result<(String, String), ToolkitError> {
    if !([16usize, 32].contains(&num_bytes) || num_bytes <= 64) || num_bytes == 0 {
        return Err(ToolkitError::InvalidInput(
            "symmetric size must be 16 or 32 bytes (up to 64 for tokens)".to_string(),
        ));
    }
    let mut b = vec![0u8; num_bytes];
    OsRng.fill_bytes(&mut b);
    let hex_s = hex::encode(&b);
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&b);
    b.zeroize();
    Ok((hex_s, b64))
}

pub fn generate_rsa(bits: usize, public_pem: &mut String, private_pem: &mut String) -> Result<(), ToolkitError> {
    if ![2048usize, 3072, 4096].contains(&bits) {
        return Err(ToolkitError::InvalidInput(
            "RSA size must be 2048, 3072, or 4096".to_string(),
        ));
    }
    use pkcs8::{EncodePrivateKey, EncodePublicKey};
    let mut rng = OsRng;
    let sk = rsa::RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?;
    let pk = rsa::RsaPublicKey::from(&sk);
    let priv_pem = sk
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?
        .to_string();
    let pub_pem = pk
        .to_public_key_pem(pkcs8::LineEnding::LF)
        .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?;
    *public_pem = pub_pem;
    *private_pem = priv_pem;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    pub fn label(self) -> &'static str {
        match self {
            EcCurve::P256 => "P-256 (ES256)",
            EcCurve::P384 => "P-384 (ES384)",
            EcCurve::P521 => "P-521 (ES512)",
        }
    }
    pub fn all() -> &'static [EcCurve] {
        &[EcCurve::P256, EcCurve::P384, EcCurve::P521]
    }
}

pub fn generate_ec(curve: EcCurve) -> Result<(String, String), ToolkitError> {
    use pkcs8::{EncodePrivateKey, EncodePublicKey};
    match curve {
        EcCurve::P256 => {
            let signing = p256::ecdsa::SigningKey::random(&mut OsRng);
            let vk = signing.verifying_key();
            let priv_pem = signing
                .to_pkcs8_pem(pkcs8::LineEnding::LF)
                .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?
                .to_string();
            let pub_pem = vk
                .to_public_key_pem(pkcs8::LineEnding::LF)
                .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?;
            Ok((pub_pem, priv_pem))
        }
        EcCurve::P384 => {
            let signing = p384::ecdsa::SigningKey::random(&mut OsRng);
            let vk = signing.verifying_key();
            let priv_pem = signing
                .to_pkcs8_pem(pkcs8::LineEnding::LF)
                .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?
                .to_string();
            let pub_pem = vk
                .to_public_key_pem(pkcs8::LineEnding::LF)
                .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?;
            Ok((pub_pem, priv_pem))
        }
        EcCurve::P521 => {
            use pkcs8::{EncodePrivateKey, EncodePublicKey};
            let sk = p521::SecretKey::random(&mut OsRng);
            let signing = p521::ecdsa::SigningKey::from_slice(&sk.to_bytes())
                .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?;
            let vk = p521::ecdsa::VerifyingKey::from(&signing);
            let _ = vk; // public PEM comes from the SecretKey-derived point below
            let priv_pem = sk
                .to_pkcs8_pem(pkcs8::LineEnding::LF)
                .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?
                .to_string();
            let pk = p521::PublicKey::from_secret_scalar(&sk.to_nonzero_scalar());
            let pub_pem = pk
                .to_public_key_pem(pkcs8::LineEnding::LF)
                .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?;
            Ok((pub_pem, priv_pem))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_sizes() {
        let (h, _) = generate_symmetric_hex(32).unwrap();
        assert_eq!(h.len(), 64);
        let (h16, _) = generate_symmetric_hex(16).unwrap();
        assert_eq!(h16.len(), 32);
    }

    #[test]
    fn ec_p256_roundtrip_sign() {
        let (pub_pem, priv_pem) = generate_ec(EcCurve::P256).unwrap();
        assert!(pub_pem.contains("PUBLIC KEY"));
        assert!(priv_pem.contains("PRIVATE KEY"));
        let t = crate::crypto::jwt::generate_token(
            crate::models::JwtAlgorithm::Es256,
            r#"{"sub":"t"}"#,
            &priv_pem,
        )
        .unwrap();
        let r = crate::crypto::jwt::verify_token(
            &t,
            crate::models::JwtAlgorithm::Es256,
            &pub_pem,
            None,
            None,
        )
        .unwrap();
        assert!(r.signature_valid);
    }
}
