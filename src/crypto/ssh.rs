//! SSH key generation and inspection.
//! - ed25519 via `ed25519-dalek` (private as PKCS#8 PEM, public as
//!   OpenSSH `authorized_keys` line).
//! - RSA via `rsa` (public formatted as OpenSSH `ssh-rsa` line).
//! - SHA256 fingerprints in the OpenSSH `SHA256:<base64>` style.

use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use base64::Engine as _;

use crate::models::ToolkitError;

fn ssh_string(s: &[u8]) -> Vec<u8> {
    let mut out = (s.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(s);
    out
}

fn ssh_mpint(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zeros, prepend zero if high bit set.
    let mut b = bytes;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    let mut out = Vec::new();
    if b.first().map(|x| x & 0x80 != 0).unwrap_or(false) {
        out.extend_from_slice(&((b.len() + 1) as u32).to_be_bytes());
        out.push(0);
    } else {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    }
    out.extend_from_slice(b);
    out
}

pub fn openssh_fingerprint(wire_blob: &[u8]) -> String {
    let digest = Sha256::digest(wire_blob);
    let mut b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    while b64.ends_with('=') {
        b64.pop();
    }
    format!("SHA256:{b64}")
}

pub struct SshKeyPair {
    pub private_pem: String,
    pub public_openssh: String,
    pub fingerprint: String,
}

pub fn generate_ed25519(comment: &str) -> Result<SshKeyPair, ToolkitError> {
    use ed25519::pkcs8::EncodePrivateKey;
    use rand::RngCore;
    // 32 CSPRNG bytes straight into the secret key (avoids rand_core
    // version coupling between rand 0.8 and ed25519-dalek 3).
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let signing = ed25519_dalek::SigningKey::from_bytes(&raw);
    raw.zeroize();
    let verifying = signing.verifying_key();
    // PKCS#8 PEM via ed25519's own pkcs8 v0.11 path.
    let private_pem = signing
        .to_pkcs8_pem(Default::default())
        .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?
        .to_string();
    let mut blob = ssh_string(b"ssh-ed25519");
    blob.extend_from_slice(&ssh_string(verifying.as_bytes()));
    let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    let comment = comment.trim();
    let public_openssh = if comment.is_empty() {
        format!("ssh-ed25519 {b64}")
    } else {
        format!("ssh-ed25519 {b64} {comment}")
    };
    Ok(SshKeyPair {
        private_pem,
        fingerprint: openssh_fingerprint(&blob),
        public_openssh,
    })
}

pub fn generate_rsa_ssh(bits: usize, comment: &str) -> Result<SshKeyPair, ToolkitError> {
    use pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    if ![2048, 3072, 4096].contains(&bits) {
        return Err(ToolkitError::InvalidInput("RSA size must be 2048, 3072, or 4096".into()));
    }
    let sk = rsa::RsaPrivateKey::new(&mut OsRng, bits)
        .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?;
    let private_pem = sk
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .map_err(|e| ToolkitError::KeyGeneration(e.to_string()))?
        .to_string();
    let pk = rsa::RsaPublicKey::from(&sk);
    let mut blob = ssh_string(b"ssh-rsa");
    blob.extend_from_slice(&ssh_mpint(&pk.e().to_bytes_be()));
    blob.extend_from_slice(&ssh_mpint(&pk.n().to_bytes_be()));
    let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    let comment = comment.trim();
    let public_openssh = if comment.is_empty() {
        format!("ssh-rsa {b64}")
    } else {
        format!("ssh-rsa {b64} {comment}")
    };
    Ok(SshKeyPair {
        private_pem,
        fingerprint: openssh_fingerprint(&blob),
        public_openssh,
    })
}

/// Parse an OpenSSH public-key line; returns (key type, fingerprint).
pub fn inspect_openssh_line(line: &str) -> Result<(String, String), ToolkitError> {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err(ToolkitError::InvalidInput("expected: <type> <base64> [comment]".into()));
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .map_err(|_| ToolkitError::InvalidBase64)?;
    if blob.len() < 11 {
        return Err(ToolkitError::InvalidInput("public key blob too short".into()));
    }
    Ok((parts[0].to_string(), openssh_fingerprint(&blob)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_format() {
        let k = generate_ed25519("test@example").unwrap();
        assert!(k.private_pem.contains("PRIVATE KEY"));
        assert!(k.public_openssh.starts_with("ssh-ed25519 "));
        assert!(k.fingerprint.starts_with("SHA256:"));
        let (t, f) = inspect_openssh_line(&k.public_openssh).unwrap();
        assert_eq!(t, "ssh-ed25519");
        assert_eq!(f, k.fingerprint);
    }

    #[test]
    fn rsa_ssh_format() {
        let k = generate_rsa_ssh(2048, "").unwrap();
        assert!(k.public_openssh.starts_with("ssh-rsa "));
    }
}
