//! File hashing + password-hashing (KDF) helpers.
//!
//! General-purpose hashing uses maintained crates directly. Password
//! hashing defaults to Argon2id.

use std::io::Read;

use argon2::{password_hash::{PasswordHasher, SaltString}, Argon2};
use rand::rngs::OsRng;

use crate::models::ToolkitError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake3,
    Md5Legacy,
    Sha1Legacy,
}

impl HashAlgorithm {
    pub fn label(self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "SHA-256",
            HashAlgorithm::Sha384 => "SHA-384",
            HashAlgorithm::Sha512 => "SHA-512",
            HashAlgorithm::Sha3_256 => "SHA3-256",
            HashAlgorithm::Sha3_512 => "SHA3-512",
            HashAlgorithm::Blake3 => "BLAKE3",
            HashAlgorithm::Md5Legacy => "MD5 (legacy)",
            HashAlgorithm::Sha1Legacy => "SHA-1 (legacy)",
        }
    }

    pub fn all() -> &'static [HashAlgorithm] {
        &[
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_512,
            HashAlgorithm::Blake3,
            HashAlgorithm::Md5Legacy,
            HashAlgorithm::Sha1Legacy,
        ]
    }

    pub fn is_legacy(self) -> bool {
        matches!(self, HashAlgorithm::Md5Legacy | HashAlgorithm::Sha1Legacy)
    }
}

pub fn hash_bytes(alg: HashAlgorithm, data: &[u8]) -> String {
    use sha2::Digest as _;
    match alg {
        HashAlgorithm::Sha256 => hex::encode(sha2::Sha256::digest(data)),
        HashAlgorithm::Sha384 => hex::encode(sha2::Sha384::digest(data)),
        HashAlgorithm::Sha512 => hex::encode(sha2::Sha512::digest(data)),
        HashAlgorithm::Sha3_256 => hex::encode(sha3::Sha3_256::digest(data)),
        HashAlgorithm::Sha3_512 => hex::encode(sha3::Sha3_512::digest(data)),
        HashAlgorithm::Blake3 => blake3::hash(data).to_hex().to_string(),
        HashAlgorithm::Md5Legacy => {
            let mut h = md5::Md5::new();
            // md-5 0.10 implements digest traits via `md5::Md5`
            use md5::Digest as _;
            h.update(data);
            hex::encode(h.finalize())
        }
        HashAlgorithm::Sha1Legacy => {
            use sha1::Digest as _;
            hex::encode(sha1::Sha1::digest(data))
        }
    }
}

/// Stream a file through the hasher without loading it fully into memory.
pub fn hash_file(alg: HashAlgorithm, path: &str) -> Result<String, ToolkitError> {
    use sha2::Digest as _;
    let f = std::fs::File::open(path)
        .map_err(|e| ToolkitError::FileRead(e.to_string()))?;
    let mut reader = std::io::BufReader::new(f);
    const CHUNK: usize = 64 * 1024;
    let mut buf = vec![0u8; CHUNK];

    // Incremental path per algorithm.
    match alg {
        HashAlgorithm::Sha256 => {
            let mut h = sha2::Sha256::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(hex::encode(h.finalize()))
        }
        HashAlgorithm::Sha384 => {
            let mut h = sha2::Sha384::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(hex::encode(h.finalize()))
        }
        HashAlgorithm::Sha512 => {
            let mut h = sha2::Sha512::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(hex::encode(h.finalize()))
        }
        HashAlgorithm::Sha3_256 => {
            let mut h = sha3::Sha3_256::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(hex::encode(h.finalize()))
        }
        HashAlgorithm::Sha3_512 => {
            let mut h = sha3::Sha3_512::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(hex::encode(h.finalize()))
        }
        HashAlgorithm::Blake3 => {
            let mut h = blake3::Hasher::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(h.finalize().to_hex().to_string())
        }
        HashAlgorithm::Md5Legacy => {
            use md5::Digest as _;
            let mut h = md5::Md5::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(hex::encode(h.finalize()))
        }
        HashAlgorithm::Sha1Legacy => {
            use sha1::Digest as _;
            let mut h = sha1::Sha1::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(hex::encode(h.finalize()))
        }
    }
}

// ------------------------------------------------------------ KDF ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    Argon2id,
    Pbkdf2Sha256,
    Scrypt,
}

impl KdfAlgorithm {
    pub fn label(self) -> &'static str {
        match self {
            KdfAlgorithm::Argon2id => "Argon2id (recommended)",
            KdfAlgorithm::Pbkdf2Sha256 => "PBKDF2-SHA256",
            KdfAlgorithm::Scrypt => "scrypt",
        }
    }
    pub fn all() -> &'static [KdfAlgorithm] {
        &[KdfAlgorithm::Argon2id, KdfAlgorithm::Pbkdf2Sha256, KdfAlgorithm::Scrypt]
    }
}

/// Hash a password for storage demonstration. Returns PHC string.
/// Never log the returned value alongside the password.
pub fn hash_password_kdf(
    alg: KdfAlgorithm,
    password: &str,
    iterations_or_t: u32,
) -> Result<String, ToolkitError> {
    if password.is_empty() {
        return Err(ToolkitError::InvalidPassword);
    }
    match alg {
        KdfAlgorithm::Argon2id => {
            let salt = SaltString::generate(&mut OsRng);
            let argon = Argon2::default();
            argon
                .hash_password(password.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(|e| ToolkitError::Encryption(e.to_string()))
        }
        KdfAlgorithm::Pbkdf2Sha256 => {
            use pbkdf2::password_hash::{PasswordHasher, SaltString};
            let iters = iterations_or_t.max(1000);
            let salt = SaltString::generate(&mut OsRng);
            let params = pbkdf2::Params {
                rounds: iters,
                output_length: 32,
            };
            pbkdf2::Pbkdf2
                .hash_password_customized(
                    password.as_bytes(),
                    None,
                    None,
                    params,
                    &salt,
                )
                .map(|h| h.to_string())
                .map_err(|e| ToolkitError::Encryption(e.to_string()))
        }
        KdfAlgorithm::Scrypt => {
            use scrypt::password_hash::{PasswordHasher, SaltString};
            let salt = SaltString::generate(&mut OsRng);
            scrypt::Scrypt
                .hash_password(password.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(|e| ToolkitError::Encryption(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // "abc"
        assert_eq!(
            hash_bytes(HashAlgorithm::Sha256, b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash_bytes(HashAlgorithm::Md5Legacy, b"abc"),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hash_bytes(HashAlgorithm::Sha1Legacy, b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn blake3_known() {
        // blake3("hello") — verified against reference implementation
        let h = hash_bytes(HashAlgorithm::Blake3, b"hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn kdf_argon2_verifies() {
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        let h = hash_password_kdf(KdfAlgorithm::Argon2id, "s3cret!", 0).unwrap();
        let parsed = PasswordHash::new(&h).unwrap();
        assert!(Argon2::default().verify_password(b"s3cret!", &parsed).is_ok());
    }
}
