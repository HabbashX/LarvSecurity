//! Encrypted vault: a JSON blob of secret entries sealed with a master
//! password through the existing Argon2id envelope (`encrypt_with_password`).
//! No new crypto — same audited path as file/text encryption.
//!
//! Entries only exist decrypted while unlocked. Locking drops them.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::encryption::{decrypt_with_password, encrypt_with_password};
use crate::models::{ArgonParams, CipherAlgorithm, ToolkitError};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultEntry {
    pub service: String,
    pub username: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultBlob {
    pub version: u8,
    pub entries: Vec<VaultEntry>,
}

pub fn seal_blob(entries: &[VaultEntry], master: &str) -> Result<String, ToolkitError> {
    let blob = VaultBlob { version: 1, entries: entries.to_vec() };
    let json = serde_json::to_string(&blob).map_err(|e| ToolkitError::Encryption(e.to_string()))?;
    encrypt_with_password(CipherAlgorithm::Aes256Gcm, json.as_bytes(), master, b"larv-vault-v1", &ArgonParams::default())
}

pub fn open_blob(envelope: &str, master: &str) -> Result<Vec<VaultEntry>, ToolkitError> {
    let pt = decrypt_with_password(envelope, master, Some(b"larv-vault-v1"))?;
    let text = String::from_utf8(pt).map_err(|_| ToolkitError::DecryptionFailed)?;
    let blob: VaultBlob = serde_json::from_str(&text).map_err(|_| ToolkitError::DecryptionFailed)?;
    if blob.version != 1 {
        return Err(ToolkitError::MalformedPackage("vault version mismatch".into()));
    }
    Ok(blob.entries)
}

/// Best-effort wipe of entry secrets held in memory.
pub fn wipe_entries(entries: &mut Vec<VaultEntry>) {
    for e in entries.iter_mut() {
        e.secret.zeroize();
        e.notes.zeroize();
        e.service.zeroize();
        e.username.zeroize();
    }
    entries.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let entries = vec![VaultEntry {
            service: "git".into(),
            username: "ada".into(),
            secret: "s3cret".into(),
            notes: String::new(),
        }];
        let env = seal_blob(&entries, "master-password-1").unwrap();
        let back = open_blob(&env, "master-password-1").unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].secret, "s3cret");
        assert!(open_blob(&env, "wrong-password-2").is_err());
    }
}
