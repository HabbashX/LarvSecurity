//! Encoding utilities. Encoding is NOT encryption.

use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};

use crate::models::ToolkitError;

pub fn base64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, ToolkitError> {
    STANDARD.decode(s.trim()).map_err(|_| ToolkitError::InvalidBase64)
}

pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn base64url_decode(s: &str) -> Result<Vec<u8>, ToolkitError> {
    URL_SAFE_NO_PAD.decode(s.trim()).map_err(|_| ToolkitError::InvalidBase64Url)
}

pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, ToolkitError> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&cleaned).map_err(|_| ToolkitError::InvalidHex)
}

pub fn url_encode(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

pub fn url_decode(s: &str) -> Result<String, ToolkitError> {
    urlencoding::decode(s.trim())
        .map(|c| c.into_owned())
        .map_err(|_| ToolkitError::InvalidInput("invalid percent-encoding".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64url_encode(b"hello"), "aGVsbG8");
        assert_eq!(hex_encode(b"hello"), "68656c6c6f");
        assert_eq!(hex_decode("68656c6c6f").unwrap(), b"hello");
        assert_eq!(url_encode("a b+c"), "a%20b%2Bc");
        assert_eq!(url_decode("a%20b%2Bc").unwrap(), "a b+c");
    }

    #[test]
    fn bad_inputs_err_no_panic() {
        assert!(base64_decode("!!!").is_err());
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("abc").is_err());
        assert!(base64url_decode("***").is_err());
    }
}
