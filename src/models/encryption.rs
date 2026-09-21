use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CipherAlgorithm {
    #[default]
    Aes256Gcm,
    Aes128Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl CipherAlgorithm {
    pub fn label(self) -> &'static str {
        match self {
            CipherAlgorithm::Aes256Gcm => "AES-256-GCM",
            CipherAlgorithm::Aes128Gcm => "AES-128-GCM",
            CipherAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            CipherAlgorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        }
    }

    pub fn all() -> &'static [CipherAlgorithm] {
        &[
            CipherAlgorithm::Aes256Gcm,
            CipherAlgorithm::Aes128Gcm,
            CipherAlgorithm::ChaCha20Poly1305,
            CipherAlgorithm::XChaCha20Poly1305,
        ]
    }

    pub fn key_len(self) -> usize {
        match self {
            CipherAlgorithm::Aes256Gcm => 32,
            CipherAlgorithm::Aes128Gcm => 16,
            CipherAlgorithm::ChaCha20Poly1305 => 32,
            CipherAlgorithm::XChaCha20Poly1305 => 32,
        }
    }

    pub fn nonce_len(self) -> usize {
        match self {
            CipherAlgorithm::Aes256Gcm => 12,
            CipherAlgorithm::Aes128Gcm => 12,
            CipherAlgorithm::ChaCha20Poly1305 => 12,
            CipherAlgorithm::XChaCha20Poly1305 => 24,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    EnvelopeJson,
    RawBase64,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::EnvelopeJson
    }
}

impl OutputFormat {
    pub fn label(self) -> &'static str {
        match self {
            OutputFormat::EnvelopeJson => "Envelope JSON (recommended)",
            OutputFormat::RawBase64 => "Raw Base64 (raw key only)",
        }
    }
}

/// Versioned envelope for password-based encryption.
///
/// Contains everything needed to decrypt later: version, algorithm,
/// KDF id + params, salt, nonce, ciphertext (+ tag, appended by AEAD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub version: u8,
    pub algorithm: String,
    pub kdf: String,
    pub argon_m_cost_kib: u32,
    pub argon_t_cost: u32,
    pub argon_p_cost: u32,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub aad_b64: Option<String>,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgonParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for ArgonParams {
    fn default() -> Self {
        // OWASP-ish interactive defaults: 64 MiB, 3 passes, 1 lane.
        Self {
            m_cost_kib: 65536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}
