//! File shredder: overwrite → rename → delete.
//! 3 passes by default (zeros, ones, CSPRNG random), chunked so large
//! files never load fully into memory.
//!
//! Honest caveat: on SSDs / journaled / copy-on-write filesystems the
//! drive may retain old blocks outside the OS's reach. Shredding raises
//! the bar; only physical destruction removes it.

use std::io::{Seek, SeekFrom, Write};

use rand::{rngs::OsRng, RngCore};

use crate::models::ToolkitError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShredPasses {
    One,
    Three,
    Seven,
}

impl ShredPasses {
    pub fn label(self) -> &'static str {
        match self {
            ShredPasses::One => "1 pass (random)",
            ShredPasses::Three => "3 passes (0x00, 0xFF, random)",
            ShredPasses::Seven => "7 passes (alternating + random)",
        }
    }
    pub fn all() -> &'static [ShredPasses] {
        &[ShredPasses::One, ShredPasses::Three, ShredPasses::Seven]
    }
    fn patterns(self) -> Vec<u8> {
        match self {
            ShredPasses::One => vec![2],
            ShredPasses::Three => vec![0, 1, 2],
            ShredPasses::Seven => vec![0, 1, 0, 1, 2, 2, 2],
        }
    }
}

/// Returns bytes overwritten.
pub fn shred_file(path: &str, passes: ShredPasses, progress: &mut dyn FnMut(u64, u64)) -> Result<u64, ToolkitError> {
    let meta = std::fs::metadata(path).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
    if !meta.is_file() {
        return Err(ToolkitError::FileRead("not a regular file".into()));
    }
    let len = meta.len();
    let pats = passes.patterns();
    let total = len * pats.len() as u64;
    let mut done = 0u64;
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| ToolkitError::FileWrite(e.to_string()))?;
        let mut chunk = vec![0u8; 64 * 1024];
        for pat in &pats {
            f.seek(SeekFrom::Start(0)).map_err(|e| ToolkitError::FileWrite(e.to_string()))?;
            let mut remaining = len;
            while remaining > 0 {
                let n = (remaining as usize).min(chunk.len());
                match pat {
                    0 => chunk[..n].fill(0x00),
                    1 => chunk[..n].fill(0xFF),
                    _ => OsRng.fill_bytes(&mut chunk[..n]),
                }
                f.write_all(&chunk[..n]).map_err(|e| ToolkitError::FileWrite(e.to_string()))?;
                remaining -= n as u64;
                done += n as u64;
                progress(done, total);
            }
            f.flush().map_err(|e| ToolkitError::FileWrite(e.to_string()))?;
        }
    }
    // Rename to a random name, then delete.
    let parent = std::path::Path::new(path).parent();
    let mut rnd = [0u8; 8];
    OsRng.fill_bytes(&mut rnd);
    if let Some(dir) = parent {
        let tmp = dir.join(format!("shredded-{}", hex::encode(rnd)));
        let _ = std::fs::rename(path, &tmp);
        std::fs::remove_file(&tmp).map_err(|e| ToolkitError::FileWrite(e.to_string()))?;
    } else {
        std::fs::remove_file(path).map_err(|e| ToolkitError::FileWrite(e.to_string()))?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shreds_temp_file() {
        let p = std::env::temp_dir().join(format!("larv-shred-{}.bin", std::process::id()));
        std::fs::write(&p, b"secret data here").unwrap();
        let n = shred_file(&p.to_string_lossy(), ShredPasses::Three, &mut |_, _| {}).unwrap();
        assert_eq!(n, 16 * 3);
        assert!(!p.exists());
    }
}
