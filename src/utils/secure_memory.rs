//! Secure-memory helpers.
//!
//! High-level languages cannot guarantee memory erasure (copies may exist
//! in buffers, swap, or the allocator). These helpers reduce exposure on
//! a best-effort basis via `zeroize`.

use zeroize::Zeroize;

/// Overwrite and clear a `String` in place.
pub fn clear_string(s: &mut String) {
    s.zeroize();
    s.clear();
}

/// Overwrite a byte vector in place.
pub fn clear_bytes(b: &mut Vec<u8>) {
    b.zeroize();
    b.clear();
}
