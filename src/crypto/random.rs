//! CSPRNG-backed random data: bytes, hex, base64, UUID, integers, tokens.

use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use rand::{rngs::OsRng, RngCore};

use crate::models::ToolkitError;

pub fn random_bytes_hex(n: usize) -> Result<String, ToolkitError> {
    check_size(n)?;
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    Ok(hex::encode(&b))
}

pub fn random_bytes_base64(n: usize) -> Result<String, ToolkitError> {
    check_size(n)?;
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    Ok(STANDARD.encode(&b))
}

pub fn random_token_urlsafe(n: usize) -> Result<String, ToolkitError> {
    check_size(n)?;
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    Ok(URL_SAFE_NO_PAD.encode(&b))
}

pub fn random_uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn random_int_inclusive(min: i64, max: i64) -> Result<i64, ToolkitError> {
    if min > max {
        return Err(ToolkitError::InvalidInput("min must be <= max".to_string()));
    }
    let range = (max as u64).wrapping_sub(min as u64).wrapping_add(1);
    if range == 0 {
        // full i64 range
        let mut buf = [0u8; 8];
        OsRng.fill_bytes(&mut buf);
        return Ok(i64::from_le_bytes(buf));
    }
    // Rejection sampling for uniformity.
    let mut buf = [0u8; 8];
    let bound = (u64::MAX / range) * range;
    loop {
        OsRng.fill_bytes(&mut buf);
        let v = u64::from_le_bytes(buf);
        if v < bound {
            return Ok(min.wrapping_add((v % range) as i64));
        }
    }
}

fn check_size(n: usize) -> Result<(), ToolkitError> {
    if n == 0 || n > 1024 * 1024 {
        return Err(ToolkitError::InvalidInput(
            "size must be between 1 and 1048576 bytes".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn sizes_match() {
        assert_eq!(random_bytes_hex(16).unwrap().len(), 32);
        assert!(!random_token_urlsafe(32).unwrap().is_empty());
    }

    #[test]
    fn uuid_unique() {
        let mut s = HashSet::new();
        for _ in 0..50 {
            s.insert(random_uuid_v4());
        }
        assert_eq!(s.len(), 50);
    }

    #[test]
    fn int_in_range() {
        for _ in 0..100 {
            let v = random_int_inclusive(1, 10).unwrap();
            assert!((1..=10).contains(&v));
        }
    }
}
