//! JWT (JWS) signing / decoding / verification.
//!
//! Implemented directly on top of audited primitives (hmac/sha2, rsa,
//! p256/p384, ecdsa+P-521) with base64url encoding. No `alg: none`, and the
//! caller must always pin the expected algorithm — the `alg` header of an
//! untrusted token is never trusted for verification.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use pkcs8::{DecodePrivateKey, DecodePublicKey};
use sha2::{Sha256, Sha384, Sha512};

use crate::models::{DecodedJwt, JwtAlgorithm, JwtVerificationReport, ToolkitError};

fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, ToolkitError> {
    URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|_| ToolkitError::InvalidBase64Url)
}

fn signing_input(header_b64: &str, payload_b64: &str) -> Vec<u8> {
    format!("{header_b64}.{payload_b64}").into_bytes()
}

fn canonical_header(alg: JwtAlgorithm) -> String {
    let header = serde_json::json!({"alg": alg.as_str(), "typ": "JWT"});
    b64url_encode(header.to_string().as_bytes())
}

fn canonical_payload(payload_json: &str) -> Result<String, ToolkitError> {
    let v: serde_json::Value =
        serde_json::from_str(payload_json).map_err(|e| ToolkitError::InvalidJson(e.to_string()))?;
    if !v.is_object() {
        return Err(ToolkitError::InvalidJson(
            "payload must be a JSON object".to_string(),
        ));
    }
    Ok(b64url_encode(v.to_string().as_bytes()))
}

fn pretty_json(raw: &str) -> Result<String, ToolkitError> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| ToolkitError::InvalidJson(e.to_string()))?;
    serde_json::to_string_pretty(&v).map_err(|e| ToolkitError::InvalidJson(e.to_string()))
}

// ---------------------------------------------------------------- HMAC ---

fn sign_hmac(alg: JwtAlgorithm, input: &[u8], secret: &[u8]) -> Result<Vec<u8>, ToolkitError> {
    if secret.len() < 32 {
        return Err(ToolkitError::WeakHmacSecret);
    }
    match alg {
        JwtAlgorithm::Hs256 => {
            let mut m = Hmac::<Sha256>::new_from_slice(secret)
                .map_err(|_| ToolkitError::InvalidInput("bad HMAC key".to_string()))?;
            m.update(input);
            Ok(m.finalize().into_bytes().to_vec())
        }
        JwtAlgorithm::Hs384 => {
            let mut m = Hmac::<Sha384>::new_from_slice(secret)
                .map_err(|_| ToolkitError::InvalidInput("bad HMAC key".to_string()))?;
            m.update(input);
            Ok(m.finalize().into_bytes().to_vec())
        }
        JwtAlgorithm::Hs512 => {
            let mut m = Hmac::<Sha512>::new_from_slice(secret)
                .map_err(|_| ToolkitError::InvalidInput("bad HMAC key".to_string()))?;
            m.update(input);
            Ok(m.finalize().into_bytes().to_vec())
        }
        _ => Err(ToolkitError::UnsupportedAlgorithm(alg.as_str().to_string())),
    }
}

fn verify_hmac(
    alg: JwtAlgorithm,
    input: &[u8],
    secret: &[u8],
    sig: &[u8],
) -> Result<bool, ToolkitError> {
    let expected = sign_hmac(alg, input, secret)?;
    if expected.len() != sig.len() {
        return Ok(false);
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(sig.iter()) {
        diff |= a ^ b;
    }
    Ok(diff == 0)
}

// ----------------------------------------------------------------- RSA ---

fn parse_rsa_private(pem: &str) -> Result<rsa::RsaPrivateKey, ToolkitError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    let trimmed = pem.trim();
    rsa::RsaPrivateKey::from_pkcs8_pem(trimmed)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(trimmed))
        .map_err(|_| ToolkitError::UnsupportedKeyFormat)
}

fn parse_rsa_public(pem: &str, priv_fallback: Option<&str>) -> Result<rsa::RsaPublicKey, ToolkitError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    let trimmed = pem.trim();
    if let Ok(k) = rsa::RsaPublicKey::from_public_key_pem(trimmed) {
        return Ok(k);
    }
    if let Ok(k) = rsa::RsaPublicKey::from_pkcs1_pem(trimmed) {
        return Ok(k);
    }
    if let Some(priv_pem) = priv_fallback {
        if let Ok(sk) = parse_rsa_private(priv_pem) {
            return Ok(rsa::RsaPublicKey::from(&sk));
        }
    }
    if let Ok(sk) = parse_rsa_private(trimmed) {
        return Ok(rsa::RsaPublicKey::from(&sk));
    }
    Err(ToolkitError::UnsupportedKeyFormat)
}

fn sign_rsa(
    alg: JwtAlgorithm,
    input: &[u8],
    private_pem: &str,
) -> Result<Vec<u8>, ToolkitError> {
    use rsa::signature::SignatureEncoding;
    use rsa::signature::Signer;
    let sk = parse_rsa_private(private_pem)?;
    match alg {
        JwtAlgorithm::Rs256 => {
            let k: rsa::pkcs1v15::SigningKey<Sha256> = rsa::pkcs1v15::SigningKey::new(sk);
            Ok(k.sign(input).to_vec())
        }
        JwtAlgorithm::Rs384 => {
            let k: rsa::pkcs1v15::SigningKey<Sha384> = rsa::pkcs1v15::SigningKey::new(sk);
            Ok(k.sign(input).to_vec())
        }
        JwtAlgorithm::Rs512 => {
            let k: rsa::pkcs1v15::SigningKey<Sha512> = rsa::pkcs1v15::SigningKey::new(sk);
            Ok(k.sign(input).to_vec())
        }
        JwtAlgorithm::Ps256 => {
            let k: rsa::pss::SigningKey<Sha256> = rsa::pss::SigningKey::new(sk);
            Ok(k.sign(input).to_vec())
        }
        JwtAlgorithm::Ps384 => {
            let k: rsa::pss::SigningKey<Sha384> = rsa::pss::SigningKey::new(sk);
            Ok(k.sign(input).to_vec())
        }
        JwtAlgorithm::Ps512 => {
            let k: rsa::pss::SigningKey<Sha512> = rsa::pss::SigningKey::new(sk);
            Ok(k.sign(input).to_vec())
        }
        _ => Err(ToolkitError::UnsupportedAlgorithm(alg.as_str().to_string())),
    }
}

fn verify_rsa(
    alg: JwtAlgorithm,
    input: &[u8],
    public_pem: &str,
    sig: &[u8],
    priv_fallback: Option<&str>,
) -> Result<bool, ToolkitError> {
    use rsa::signature::Verifier;
    let pk = parse_rsa_public(public_pem, priv_fallback)?;
    let ok = match alg {
        JwtAlgorithm::Rs256 => {
            let vk: rsa::pkcs1v15::VerifyingKey<Sha256> = rsa::pkcs1v15::VerifyingKey::new(pk);
            let s = rsa::pkcs1v15::Signature::try_from(sig)
                .map_err(|_| ToolkitError::InvalidSignature)?;
            vk.verify(input, &s).is_ok()
        }
        JwtAlgorithm::Rs384 => {
            let vk: rsa::pkcs1v15::VerifyingKey<Sha384> = rsa::pkcs1v15::VerifyingKey::new(pk);
            let s = rsa::pkcs1v15::Signature::try_from(sig)
                .map_err(|_| ToolkitError::InvalidSignature)?;
            vk.verify(input, &s).is_ok()
        }
        JwtAlgorithm::Rs512 => {
            let vk: rsa::pkcs1v15::VerifyingKey<Sha512> = rsa::pkcs1v15::VerifyingKey::new(pk);
            let s = rsa::pkcs1v15::Signature::try_from(sig)
                .map_err(|_| ToolkitError::InvalidSignature)?;
            vk.verify(input, &s).is_ok()
        }
        JwtAlgorithm::Ps256 => {
            let vk: rsa::pss::VerifyingKey<Sha256> = rsa::pss::VerifyingKey::new(pk);
            let s = rsa::pss::Signature::try_from(sig)
                .map_err(|_| ToolkitError::InvalidSignature)?;
            vk.verify(input, &s).is_ok()
        }
        JwtAlgorithm::Ps384 => {
            let vk: rsa::pss::VerifyingKey<Sha384> = rsa::pss::VerifyingKey::new(pk);
            let s = rsa::pss::Signature::try_from(sig)
                .map_err(|_| ToolkitError::InvalidSignature)?;
            vk.verify(input, &s).is_ok()
        }
        JwtAlgorithm::Ps512 => {
            let vk: rsa::pss::VerifyingKey<Sha512> = rsa::pss::VerifyingKey::new(pk);
            let s = rsa::pss::Signature::try_from(sig)
                .map_err(|_| ToolkitError::InvalidSignature)?;
            vk.verify(input, &s).is_ok()
        }
        _ => return Err(ToolkitError::UnsupportedAlgorithm(alg.as_str().to_string())),
    };
    Ok(ok)
}

// ------------------------------------------------------------------ EC ---

fn parse_p256_signing(pem: &str) -> Result<p256::ecdsa::SigningKey, ToolkitError> {
    let trimmed = pem.trim();
    p256::ecdsa::SigningKey::from_pkcs8_pem(trimmed)
        .or_else(|_| {
            use sec1::DecodeEcPrivateKey;
            p256::SecretKey::from_sec1_pem(trimmed).map(|sk| {
                let bytes = sk.to_bytes();
                p256::ecdsa::SigningKey::from_bytes(&bytes).expect("valid SEC1 key")
            })
        })
        .map_err(|_| ToolkitError::UnsupportedKeyFormat)
}

fn parse_p384_signing(pem: &str) -> Result<p384::ecdsa::SigningKey, ToolkitError> {
    let trimmed = pem.trim();
    p384::ecdsa::SigningKey::from_pkcs8_pem(trimmed)
        .or_else(|_| {
            use sec1::DecodeEcPrivateKey;
            p384::SecretKey::from_sec1_pem(trimmed).map(|sk| {
                let bytes = sk.to_bytes();
                p384::ecdsa::SigningKey::from_bytes(&bytes).expect("valid SEC1 key")
            })
        })
        .map_err(|_| ToolkitError::UnsupportedKeyFormat)
}

fn parse_p521_signing(pem: &str) -> Result<p521::ecdsa::SigningKey, ToolkitError> {
    // P-521 has no deterministic RFC6979 impl, so the generic
    // `ecdsa::SigningKey<NistP521>` offers no `Signer`. Use the p521
    // wrapper (randomized ECDSA, valid for JWS) bridged via SecretKey.
    let trimmed = pem.trim();
    let sk = p521::SecretKey::from_pkcs8_pem(trimmed)
        .or_else(|_| {
            use sec1::DecodeEcPrivateKey;
            p521::SecretKey::from_sec1_pem(trimmed)
        })
        .map_err(|_| ToolkitError::UnsupportedKeyFormat)?;
    p521::ecdsa::SigningKey::from_slice(&sk.to_bytes())
        .map_err(|_| ToolkitError::UnsupportedKeyFormat)
}

fn parse_p256_verifying(pem: &str) -> Result<p256::ecdsa::VerifyingKey, ToolkitError> {
    p256::ecdsa::VerifyingKey::from_public_key_pem(pem.trim())
        .map_err(|_| ToolkitError::UnsupportedKeyFormat)
}

fn parse_p384_verifying(pem: &str) -> Result<p384::ecdsa::VerifyingKey, ToolkitError> {
    p384::ecdsa::VerifyingKey::from_public_key_pem(pem.trim())
        .map_err(|_| ToolkitError::UnsupportedKeyFormat)
}

fn parse_p521_verifying(pem: &str) -> Result<p521::ecdsa::VerifyingKey, ToolkitError> {
    let pk = p521::PublicKey::from_public_key_pem(pem.trim())
        .map_err(|_| ToolkitError::UnsupportedKeyFormat)?;
    p521::ecdsa::VerifyingKey::from_sec1_bytes(pk.to_sec1_bytes().as_ref())
        .map_err(|_| ToolkitError::UnsupportedKeyFormat)
}

fn sign_ec(
    alg: JwtAlgorithm,
    input: &[u8],
    private_pem: &str,
) -> Result<Vec<u8>, ToolkitError> {
    use signature::Signer;
    match alg {
        JwtAlgorithm::Es256 => {
            let key = parse_p256_signing(private_pem)?;
            let sig: p256::ecdsa::Signature = key.sign(input);
            Ok(sig.to_der().as_bytes().to_vec())
        }
        JwtAlgorithm::Es384 => {
            let key = parse_p384_signing(private_pem)?;
            let sig: p384::ecdsa::Signature = key.sign(input);
            Ok(sig.to_der().as_bytes().to_vec())
        }
        JwtAlgorithm::Es512 => {
            let key = parse_p521_signing(private_pem)?;
            let sig: p521::ecdsa::Signature = key.sign(input);
            Ok(sig.to_der().as_bytes().to_vec())
        }
        _ => Err(ToolkitError::UnsupportedAlgorithm(alg.as_str().to_string())),
    }
}

fn verify_ec(
    alg: JwtAlgorithm,
    input: &[u8],
    public_pem: &str,
    sig_bytes: &[u8],
) -> Result<bool, ToolkitError> {
    use signature::Verifier;
    match alg {
        JwtAlgorithm::Es256 => {
            let vk = parse_p256_verifying(public_pem)?;
            if let Ok(sig) = p256::ecdsa::Signature::from_der(sig_bytes) {
                if vk.verify(input, &sig).is_ok() {
                    return Ok(true);
                }
            }
            if let Ok(raw) = p256::ecdsa::Signature::from_slice(sig_bytes) {
                return Ok(vk.verify(input, &raw).is_ok());
            }
            Ok(false)
        }
        JwtAlgorithm::Es384 => {
            let vk = parse_p384_verifying(public_pem)?;
            if let Ok(sig) = p384::ecdsa::Signature::from_der(sig_bytes) {
                if vk.verify(input, &sig).is_ok() {
                    return Ok(true);
                }
            }
            if let Ok(raw) = p384::ecdsa::Signature::from_slice(sig_bytes) {
                return Ok(vk.verify(input, &raw).is_ok());
            }
            Ok(false)
        }
        JwtAlgorithm::Es512 => {
            let vk = parse_p521_verifying(public_pem)?;
            if let Ok(sig) = p521::ecdsa::Signature::from_der(sig_bytes) {
                if vk.verify(input, &sig).is_ok() {
                    return Ok(true);
                }
            }
            if let Ok(raw) = p521::ecdsa::Signature::from_slice(sig_bytes) {
                return Ok(vk.verify(input, &raw).is_ok());
            }
            Ok(false)
        }
        _ => Err(ToolkitError::UnsupportedAlgorithm(alg.as_str().to_string())),
    }
}

/// JWS requires ECDSA signatures as raw R||S, not DER. Convert DER -> raw
/// with fixed coordinate sizes (32 / 48 / 66 bytes).
fn der_to_raw_rs(alg: JwtAlgorithm, der: &[u8]) -> Result<Vec<u8>, ToolkitError> {
    fn split_der(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ToolkitError> {
        let mut pos = 0;
        let take = |pos: &mut usize, n: usize| -> Result<&[u8], ToolkitError> {
            if *pos + n > der.len() {
                return Err(ToolkitError::InvalidSignature);
            }
            let s = &der[*pos..*pos + n];
            *pos += n;
            Ok(s)
        };
        let read_len = |pos: &mut usize| -> Result<usize, ToolkitError> {
            let b = take(pos, 1)?[0] as usize;
            if b & 0x80 == 0 {
                Ok(b)
            } else {
                let n = b & 0x7f;
                if n == 0 || n > 4 {
                    return Err(ToolkitError::InvalidSignature);
                }
                let bytes = take(pos, n)?;
                let mut v = 0usize;
                for b in bytes {
                    v = (v << 8) | (*b as usize);
                }
                Ok(v)
            }
        };
        if take(&mut pos, 1)?[0] != 0x30 {
            return Err(ToolkitError::InvalidSignature);
        }
        let _seq = read_len(&mut pos)?;
        if take(&mut pos, 1)?[0] != 0x02 {
            return Err(ToolkitError::InvalidSignature);
        }
        let rl = read_len(&mut pos)?;
        let r = take(&mut pos, rl)?.to_vec();
        if take(&mut pos, 1)?[0] != 0x02 {
            return Err(ToolkitError::InvalidSignature);
        }
        let sl = read_len(&mut pos)?;
        let s = take(&mut pos, sl)?.to_vec();
        Ok((r, s))
    }
    let coord = match alg {
        JwtAlgorithm::Es256 => 32,
        JwtAlgorithm::Es384 => 48,
        JwtAlgorithm::Es512 => 66,
        _ => return Err(ToolkitError::UnsupportedAlgorithm(alg.as_str().to_string())),
    };
    let (mut r, mut s) = split_der(der)?;
    while r.len() > coord && r.first() == Some(&0) {
        r.remove(0);
    }
    while s.len() > coord && s.first() == Some(&0) {
        s.remove(0);
    }
    if r.len() > coord || s.len() > coord {
        return Err(ToolkitError::InvalidSignature);
    }
    let mut raw = vec![0u8; coord * 2];
    raw[coord - r.len()..coord].copy_from_slice(&r);
    raw[2 * coord - s.len()..].copy_from_slice(&s);
    Ok(raw)
}

// ------------------------------------------------------------------ API ---

/// Generate a signed JWT (JWS, compact serialization).
pub fn generate_token(
    alg: JwtAlgorithm,
    payload_json: &str,
    key_material: &str,
) -> Result<String, ToolkitError> {
    let header_b64 = canonical_header(alg);
    let payload_b64 = canonical_payload(payload_json)?;
    let input = signing_input(&header_b64, &payload_b64);
    let sig: Vec<u8> = if alg.is_hmac() {
        sign_hmac(alg, &input, key_material.as_bytes())?
    } else if alg.is_rsa() {
        sign_rsa(alg, &input, key_material)?
    } else {
        let der = sign_ec(alg, &input, key_material)?;
        der_to_raw_rs(alg, &der)?
    };
    Ok(format!(
        "{header_b64}.{payload_b64}.{}",
        b64url_encode(&sig)
    ))
}

/// Decode without verifying. Never trust the result.
pub fn decode_token(token: &str) -> Result<DecodedJwt, ToolkitError> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(ToolkitError::InvalidJwtFormat);
    }
    let header_raw =
        String::from_utf8(b64url_decode(parts[0])?).map_err(|_| ToolkitError::InvalidJwtFormat)?;
    let payload_raw =
        String::from_utf8(b64url_decode(parts[1])?).map_err(|_| ToolkitError::InvalidJwtFormat)?;
    let header_json = pretty_json(&header_raw)?;
    let payload_json = pretty_json(&payload_raw)?;
    let header_v: serde_json::Value =
        serde_json::from_str(&header_raw).map_err(|e| ToolkitError::InvalidJson(e.to_string()))?;
    let alg = header_v
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    Ok(DecodedJwt {
        header_json,
        payload_json,
        signature_b64url: parts[2].to_string(),
        algorithm: alg,
    })
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn claim_warnings(
    payload: &serde_json::Value,
    expected_iss: Option<&str>,
    expected_aud: Option<&str>,
) -> Vec<String> {
    let mut w = Vec::new();
    match payload.get("exp").and_then(|v| v.as_i64()) {
        Some(exp) => {
            if exp <= now_epoch() {
                w.push("Token is expired (exp in the past).".to_string());
            }
        }
        None => w.push("Missing exp claim; token never expires.".to_string()),
    }
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
        if nbf > now_epoch() {
            w.push("Token not yet valid (nbf in the future).".to_string());
        }
    }
    if let Some(iss) = expected_iss {
        let ok = payload.get("iss").and_then(|v| v.as_str()) == Some(iss);
        if !ok {
            w.push("Issuer (iss) does not match expected value.".to_string());
        }
    }
    if let Some(aud) = expected_aud {
        let ok = match payload.get("aud") {
            Some(serde_json::Value::String(s)) => s == aud,
            Some(serde_json::Value::Array(arr)) => {
                arr.iter().any(|v| v.as_str() == Some(aud))
            }
            _ => false,
        };
        if !ok {
            w.push("Audience (aud) does not match expected value.".to_string());
        }
    }
    w
}

/// Verify a token against an explicitly pinned expected algorithm.
pub fn verify_token(
    token: &str,
    expected: JwtAlgorithm,
    key_material: &str,
    expected_iss: Option<&str>,
    expected_aud: Option<&str>,
) -> Result<JwtVerificationReport, ToolkitError> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(ToolkitError::InvalidJwtFormat);
    }
    let header_raw =
        String::from_utf8(b64url_decode(parts[0])?).map_err(|_| ToolkitError::InvalidJwtFormat)?;
    let payload_raw =
        String::from_utf8(b64url_decode(parts[1])?).map_err(|_| ToolkitError::InvalidJwtFormat)?;
    let sig = b64url_decode(parts[2])?;
    let header_v: serde_json::Value =
        serde_json::from_str(&header_raw).map_err(|e| ToolkitError::InvalidJson(e.to_string()))?;
    let payload_v: serde_json::Value =
        serde_json::from_str(&payload_raw).map_err(|e| ToolkitError::InvalidJson(e.to_string()))?;
    let token_alg = header_v
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if token_alg != expected.as_str() {
        return Err(ToolkitError::AlgorithmMismatch {
            token_alg: if token_alg.is_empty() {
                "(missing)".to_string()
            } else {
                token_alg
            },
            expected_alg: expected.as_str().to_string(),
        });
    }
    if token_alg.eq_ignore_ascii_case("none") {
        return Err(ToolkitError::UnsupportedAlgorithm("none".to_string()));
    }

    let input = signing_input(parts[0].trim(), parts[1].trim());
    let signature_valid = if expected.is_hmac() {
        verify_hmac(expected, &input, key_material.as_bytes(), &sig)?
    } else if expected.is_rsa() {
        verify_rsa(expected, &input, key_material, &sig, Some(key_material))?
    } else {
        verify_ec(expected, &input, key_material, &sig)?
    };

    if !signature_valid {
        return Ok(JwtVerificationReport {
            signature_valid: false,
            algorithm: expected.as_str().to_string(),
            expired: None,
            not_yet_valid: None,
            warnings: vec!["Signature invalid. Do not trust this token.".to_string()],
        });
    }

    let now = now_epoch();
    let expired = payload_v
        .get("exp")
        .and_then(|v| v.as_i64())
        .map(|exp| exp <= now);
    let not_yet_valid = payload_v
        .get("nbf")
        .and_then(|v| v.as_i64())
        .map(|nbf| nbf > now);
    let mut warnings = claim_warnings(&payload_v, expected_iss, expected_aud);
    if expected.is_hmac() && key_material.as_bytes().len() < 32 {
        warnings.push("Weak HMAC secret (< 32 bytes).".to_string());
    }
    Ok(JwtVerificationReport {
        signature_valid: true,
        algorithm: expected.as_str().to_string(),
        expired,
        not_yet_valid,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &str = r#"{"sub":"123","role":"ADMIN","iat":1720000000,"exp":1999999999}"#;

    #[test]
    fn hs256_roundtrip() {
        let secret = "this-is-a-very-long-test-secret-32b!!";
        let t = generate_token(JwtAlgorithm::Hs256, PAYLOAD, secret).unwrap();
        let r = verify_token(&t, JwtAlgorithm::Hs256, secret, None, None).unwrap();
        assert!(r.signature_valid);
    }

    #[test]
    fn hs256_wrong_secret_fails() {
        let t = generate_token(
            JwtAlgorithm::Hs256,
            PAYLOAD,
            "this-is-a-very-long-test-secret-32b!!",
        )
        .unwrap();
        let r = verify_token(
            &t,
            JwtAlgorithm::Hs256,
            "another-very-long-test-secret-00000!!",
            None,
            None,
        )
        .unwrap();
        assert!(!r.signature_valid);
    }

    #[test]
    fn rejects_alg_mismatch() {
        let secret = "this-is-a-very-long-test-secret-32b!!";
        let t = generate_token(JwtAlgorithm::Hs256, PAYLOAD, secret).unwrap();
        let e = verify_token(&t, JwtAlgorithm::Hs384, secret, None, None).unwrap_err();
        assert!(matches!(e, ToolkitError::AlgorithmMismatch { .. }));
    }

    #[test]
    fn decode_splits_parts() {
        let secret = "this-is-a-very-long-test-secret-32b!!";
        let t = generate_token(JwtAlgorithm::Hs256, PAYLOAD, secret).unwrap();
        let d = decode_token(&t).unwrap();
        assert_eq!(d.algorithm, "HS256");
        assert!(d.payload_json.contains("ADMIN"));
    }

    #[test]
    fn malformed_rejected() {
        assert!(decode_token("not.a").is_err());
        assert!(decode_token("a.b.c.d").is_err());
    }

    #[test]
    fn weak_secret_rejected_on_sign() {
        assert!(generate_token(JwtAlgorithm::Hs256, PAYLOAD, "short").is_err());
    }
}
