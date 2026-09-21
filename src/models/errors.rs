use thiserror::Error;

/// Structured application errors. Never expose secrets or key material.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ToolkitError {
    #[error("Invalid JWT format: expected three dot-separated segments")]
    InvalidJwtFormat,
    #[error("Invalid JSON payload: {0}")]
    InvalidJson(String),
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Expired token")]
    ExpiredToken,
    #[error("Token not yet valid (nbf)")]
    NotYetValid,
    #[error("Invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Invalid Base64 input")]
    InvalidBase64,
    #[error("Invalid Base64URL input")]
    InvalidBase64Url,
    #[error("Invalid hex input")]
    InvalidHex,
    #[error("Decryption failed: authentication tag verification failed or invalid password")]
    DecryptionFailed,
    #[error("Invalid password")]
    InvalidPassword,
    #[error("File could not be read: {0}")]
    FileRead(String),
    #[error("File could not be written: {0}")]
    FileWrite(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Algorithm mismatch: token uses {token_alg}, expected {expected_alg}")]
    AlgorithmMismatch {
        token_alg: String,
        expected_alg: String,
    },
    #[error("Weak HMAC secret: use at least 32 bytes (256 bits)")]
    WeakHmacSecret,
    #[error("Missing expiration claim (exp)")]
    MissingExpiration,
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Malformed encrypted package: {0}")]
    MalformedPackage(String),
    #[error("Unsupported key format")]
    UnsupportedKeyFormat,
    #[error("Password policy violation: {0}")]
    PolicyViolation(String),
    #[error("Operation failed: {0}")]
    Other(String),
}

/// Short user-facing hint for an error (used in status bars).
pub fn user_hint(e: &ToolkitError) -> &'static str {
    match e {
        ToolkitError::InvalidJwtFormat => "Paste a token shaped like header.payload.signature.",
        ToolkitError::InvalidJson(_) => "Check JSON syntax (quotes, commas, braces).",
        ToolkitError::UnsupportedAlgorithm(_) => "Select an algorithm listed in the dropdown.",
        ToolkitError::InvalidSignature => "Signature bytes do not match. Check key and algorithm.",
        ToolkitError::ExpiredToken => "Token exp is in the past.",
        ToolkitError::NotYetValid => "Token nbf is in the future.",
        ToolkitError::InvalidKeyLength { .. } => "Provide a key of exactly the required size.",
        ToolkitError::InvalidBase64 => "Base64 must use A-Z a-z 0-9 + / with = padding.",
        ToolkitError::InvalidBase64Url => "Base64URL must use A-Z a-z 0-9 - _ without padding.",
        ToolkitError::InvalidHex => "Hex must be 0-9 a-f with even length.",
        ToolkitError::DecryptionFailed => "Wrong password/key, or data was modified.",
        ToolkitError::InvalidPassword => "Check the password and try again.",
        ToolkitError::FileRead(_) => "Check the path and file permissions.",
        ToolkitError::FileWrite(_) => "Check the destination path and disk space.",
        ToolkitError::InvalidInput(_) => "Adjust the highlighted field.",
        ToolkitError::AlgorithmMismatch { .. } => "Verification must pin the expected algorithm.",
        ToolkitError::WeakHmacSecret => "Use a longer random secret (>= 32 bytes).",
        ToolkitError::MissingExpiration => "Consider adding an exp claim.",
        ToolkitError::KeyGeneration(_) => "Retry key generation.",
        ToolkitError::Encryption(_) => "Check algorithm and inputs, then retry.",
        ToolkitError::MalformedPackage(_) => "The encrypted JSON/Base64 envelope is damaged.",
        ToolkitError::UnsupportedKeyFormat => "Paste PKCS#8 / PKCS#1 / SEC1 PEM.",
        ToolkitError::PolicyViolation(_) => "Adjust length or minimum counts.",
        ToolkitError::Other(_) => "See details and retry.",
    }
}
