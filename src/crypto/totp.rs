//! HOTP (RFC 4226) + TOTP (RFC 6238): HMAC-based one-time passwords.
//! Secrets are base32 (RFC 4648, no padding) as in authenticator apps.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::models::ToolkitError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpHash {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpHash {
    pub fn label(self) -> &'static str {
        match self {
            TotpHash::Sha1 => "SHA-1",
            TotpHash::Sha256 => "SHA-256",
            TotpHash::Sha512 => "SHA-512",
        }
    }
    pub fn all() -> &'static [TotpHash] {
        &[TotpHash::Sha1, TotpHash::Sha256, TotpHash::Sha512]
    }
}

/// Decode a user-supplied secret: base32 (with/without padding, any case)
/// or raw UTF-8 fallback for test vectors.
pub fn decode_secret(input: &str) -> Result<Vec<u8>, ToolkitError> {
    let t = input.trim().replace([' ', '\n', '\r', '\t', '-'], "");
    if t.is_empty() {
        return Err(ToolkitError::InvalidInput("secret must not be empty".into()));
    }
    // Try base32 (uppercased, padding restored).
    let mut up = t.to_uppercase();
    while up.len() % 8 != 0 {
        up.push('=');
    }
    if let Ok(b) = data_encoding::BASE32.decode(up.as_bytes()) {
        if !b.is_empty() {
            return Ok(b);
        }
    }
    // Fallback: raw ASCII (used by RFC test vectors).
    if t.is_ascii() {
        return Ok(t.into_bytes());
    }
    Err(ToolkitError::InvalidInput("secret must be base32 or ASCII".into()))
}

pub fn encode_secret_base32(secret: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(secret)
}

pub fn random_secret_base32(num_bytes: usize) -> String {
    use rand::{rngs::OsRng, RngCore};
    let mut b = vec![0u8; num_bytes.clamp(10, 64)];
    OsRng.fill_bytes(&mut b);
    encode_secret_base32(&b)
}

fn hotp_raw(secret: &[u8], hash: TotpHash, counter: u64, digits: u32) -> Result<String, ToolkitError> {
    if !(6..=8).contains(&digits) {
        return Err(ToolkitError::InvalidInput("digits must be 6, 7, or 8".into()));
    }
    let msg = counter.to_be_bytes();
    let hash_bytes: Vec<u8> = match hash {
        TotpHash::Sha1 => {
            let mut m = Hmac::<Sha1>::new_from_slice(secret)
                .map_err(|_| ToolkitError::InvalidInput("bad secret".into()))?;
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpHash::Sha256 => {
            let mut m = Hmac::<Sha256>::new_from_slice(secret)
                .map_err(|_| ToolkitError::InvalidInput("bad secret".into()))?;
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpHash::Sha512 => {
            let mut m = Hmac::<Sha512>::new_from_slice(secret)
                .map_err(|_| ToolkitError::InvalidInput("bad secret".into()))?;
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
    };
    let offset = (hash_bytes[hash_bytes.len() - 1] & 0x0f) as usize;
    let code = ((hash_bytes[offset] as u32 & 0x7f) << 24)
        | ((hash_bytes[offset + 1] as u32) << 16)
        | ((hash_bytes[offset + 2] as u32) << 8)
        | (hash_bytes[offset + 3] as u32);
    let modulo = 10u32.pow(digits);
    Ok(format!("{:01$}", code % modulo, digits as usize))
}

/// HOTP value for an explicit counter.
pub fn hotp(secret: &[u8], hash: TotpHash, counter: u64, digits: u32) -> Result<String, ToolkitError> {
    hotp_raw(secret, hash, counter, digits)
}

/// TOTP value for a Unix timestamp.
pub fn totp_at(secret: &[u8], hash: TotpHash, unix_secs: u64, step_secs: u64, digits: u32) -> Result<String, ToolkitError> {
    if step_secs == 0 || step_secs > 3600 {
        return Err(ToolkitError::InvalidInput("step must be 1..=3600s".into()));
    }
    hotp_raw(secret, hash, unix_secs / step_secs, digits)
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verify a TOTP code allowing ±`window` steps of clock skew.
pub fn verify_totp(secret: &[u8], hash: TotpHash, unix_secs: u64, step_secs: u64, digits: u32, code: &str, window: u64) -> Result<bool, ToolkitError> {
    let t = code.trim();
    if t.len() != digits as usize || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(false);
    }
    let center = unix_secs / step_secs;
    let lo = center.saturating_sub(window);
    for c in lo..=center + window {
        if hotp_raw(secret, hash, c, digits)? == t {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Build an `otpauth://` URI for QR export / app import.
pub fn otpauth_uri(kind: &str, label: &str, secret_b32: &str, hash: TotpHash, digits: u32, step: u64) -> String {
    let algo = match hash {
        TotpHash::Sha1 => "SHA1",
        TotpHash::Sha256 => "SHA256",
        TotpHash::Sha512 => "SHA512",
    };
    format!(
        "otpauth://{kind}/{label}?secret={secret_b32}&algorithm={algo}&digits={digits}&period={step}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238 Appendix B, 8-digit.
        let s = b"12345678901234567890";
        assert_eq!(totp_at(s, TotpHash::Sha1, 59, 30, 8).unwrap(), "94287082");
        assert_eq!(totp_at(s, TotpHash::Sha1, 1111111109, 30, 8).unwrap(), "07081804");
        assert_eq!(totp_at(s, TotpHash::Sha1, 2000000000, 30, 8).unwrap(), "69279037");
    }

    #[test]
    fn rfc6238_sha256_sha512_vectors() {
        let s256 = b"12345678901234567890123456789012";
        assert_eq!(totp_at(s256, TotpHash::Sha256, 59, 30, 8).unwrap(), "46119246");
        let s512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        assert_eq!(totp_at(s512, TotpHash::Sha512, 59, 30, 8).unwrap(), "90693936");
    }

    #[test]
    fn rfc4226_hotp_vectors() {
        let s = b"12345678901234567890";
        let expected = ["755224", "287082", "359152", "969429", "338314"];
        for (i, e) in expected.iter().enumerate() {
            assert_eq!(hotp(s, TotpHash::Sha1, i as u64, 6).unwrap(), *e);
        }
    }

    #[test]
    fn base32_roundtrip() {
        let raw = decode_secret("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(encode_secret_base32(&raw), "JBSWY3DPEHPK3PXP");
    }
}
