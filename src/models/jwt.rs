use serde::{Deserialize, Serialize};

/// Supported JWT signing algorithms. Only algorithms with a safe
/// implementation in this codebase are exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum JwtAlgorithm {
    #[default]
    Hs256,
    Hs384,
    Hs512,
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    Es512,
}

impl JwtAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            JwtAlgorithm::Hs256 => "HS256",
            JwtAlgorithm::Hs384 => "HS384",
            JwtAlgorithm::Hs512 => "HS512",
            JwtAlgorithm::Rs256 => "RS256",
            JwtAlgorithm::Rs384 => "RS384",
            JwtAlgorithm::Rs512 => "RS512",
            JwtAlgorithm::Ps256 => "PS256",
            JwtAlgorithm::Ps384 => "PS384",
            JwtAlgorithm::Ps512 => "PS512",
            JwtAlgorithm::Es256 => "ES256",
            JwtAlgorithm::Es384 => "ES384",
            JwtAlgorithm::Es512 => "ES512",
        }
    }

    pub fn all() -> &'static [JwtAlgorithm] {
        &[
            JwtAlgorithm::Hs256,
            JwtAlgorithm::Hs384,
            JwtAlgorithm::Hs512,
            JwtAlgorithm::Rs256,
            JwtAlgorithm::Rs384,
            JwtAlgorithm::Rs512,
            JwtAlgorithm::Ps256,
            JwtAlgorithm::Ps384,
            JwtAlgorithm::Ps512,
            JwtAlgorithm::Es256,
            JwtAlgorithm::Es384,
            JwtAlgorithm::Es512,
        ]
    }

    pub fn from_str(s: &str) -> Option<JwtAlgorithm> {
        match s {
            "HS256" => Some(JwtAlgorithm::Hs256),
            "HS384" => Some(JwtAlgorithm::Hs384),
            "HS512" => Some(JwtAlgorithm::Hs512),
            "RS256" => Some(JwtAlgorithm::Rs256),
            "RS384" => Some(JwtAlgorithm::Rs384),
            "RS512" => Some(JwtAlgorithm::Rs512),
            "PS256" => Some(JwtAlgorithm::Ps256),
            "PS384" => Some(JwtAlgorithm::Ps384),
            "PS512" => Some(JwtAlgorithm::Ps512),
            "ES256" => Some(JwtAlgorithm::Es256),
            "ES384" => Some(JwtAlgorithm::Es384),
            "ES512" => Some(JwtAlgorithm::Es512),
            _ => None,
        }
    }

    pub fn is_hmac(self) -> bool {
        matches!(
            self,
            JwtAlgorithm::Hs256 | JwtAlgorithm::Hs384 | JwtAlgorithm::Hs512
        )
    }

    pub fn is_rsa(self) -> bool {
        matches!(
            self,
            JwtAlgorithm::Rs256
                | JwtAlgorithm::Rs384
                | JwtAlgorithm::Rs512
                | JwtAlgorithm::Ps256
                | JwtAlgorithm::Ps384
                | JwtAlgorithm::Ps512
        )
    }

    pub fn is_ec(self) -> bool {
        matches!(
            self,
            JwtAlgorithm::Es256 | JwtAlgorithm::Es384 | JwtAlgorithm::Es512
        )
    }
}

/// Decoded (unverified) view of a JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedJwt {
    pub header_json: String,
    pub payload_json: String,
    pub signature_b64url: String,
    pub algorithm: String,
}

/// Result of signature + claim inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtVerificationReport {
    pub signature_valid: bool,
    pub algorithm: String,
    pub expired: Option<bool>,
    pub not_yet_valid: Option<bool>,
    pub warnings: Vec<String>,
}
