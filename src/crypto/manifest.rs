//! Checksum manifests: hash every file under a folder into a
//! `.sha256`-style manifest, then verify the folder later.
//! Files stream in 64 KiB chunks; paths stored relative to the root.

use std::path::{Path, PathBuf};

use crate::crypto::hashing::{hash_file, HashAlgorithm};
use crate::models::ToolkitError;

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), ToolkitError> {
    let rd = std::fs::read_dir(dir).map_err(|e| ToolkitError::FileRead(e.to_string()))?;
    let mut entries: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            walk(&p, out)?;
        } else if p.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

/// Build manifest text: `<hex>  <relative/path>` per line.
pub fn build_manifest(root: &str, alg: HashAlgorithm) -> Result<String, ToolkitError> {
    let root_p = Path::new(root);
    if !root_p.is_dir() {
        return Err(ToolkitError::FileRead("select a folder".into()));
    }
    let mut files = Vec::new();
    walk(root_p, &mut files)?;
    let mut lines = vec![format!("# LarvSecurity manifest · {} · {}", alg.label(), root)];
    for f in files {
        let rel = f.strip_prefix(root_p).unwrap_or(&f).to_string_lossy().replace('\\', "/");
        let h = hash_file(alg, &f.to_string_lossy())?;
        lines.push(format!("{h}  {rel}"));
    }
    Ok(lines.join("\n"))
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub ok: usize,
    pub missing: Vec<String>,
    pub mismatched: Vec<String>,
    pub extra_note: String,
}

/// Verify a folder against manifest text.
pub fn verify_manifest(root: &str, manifest: &str, alg: HashAlgorithm) -> Result<VerifyReport, ToolkitError> {
    let root_p = Path::new(root);
    let mut ok = 0usize;
    let mut missing = Vec::new();
    let mut mismatched = Vec::new();
    let mut entries = 0usize;
    for line in manifest.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        let (Some(h), Some(rel)) = (it.next(), it.next()) else {
            continue;
        };
        let rel = rel.trim();
        entries += 1;
        let full = root_p.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        if !full.is_file() {
            missing.push(rel.to_string());
            continue;
        }
        let got = hash_file(alg, &full.to_string_lossy())?;
        if got.eq_ignore_ascii_case(h.trim()) {
            ok += 1;
        } else {
            mismatched.push(rel.to_string());
        }
    }
    Ok(VerifyReport {
        ok,
        missing,
        mismatched,
        extra_note: format!("{entries} entries checked with {}", alg.label()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_on_temp_dir() {
        let dir = std::env::temp_dir().join(format!("larv-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello").unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("b.bin"), b"\x00\x01\x02").unwrap();
        let m = build_manifest(&dir.to_string_lossy(), HashAlgorithm::Sha256).unwrap();
        let r = verify_manifest(&dir.to_string_lossy(), &m, HashAlgorithm::Sha256).unwrap();
        assert_eq!(r.ok, 2);
        assert!(r.missing.is_empty() && r.mismatched.is_empty());
        // Tamper → mismatch.
        std::fs::write(dir.join("a.txt"), b"HELLO").unwrap();
        let r2 = verify_manifest(&dir.to_string_lossy(), &m, HashAlgorithm::Sha256).unwrap();
        assert_eq!(r2.mismatched.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
