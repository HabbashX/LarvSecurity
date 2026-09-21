//! Opt-in online checks. OFF by default — the app is local-first.
//! - Password breach check via HaveIBeenPwned k-anonymity range API:
//!   only the first 5 hex chars of SHA-1(password) leave the machine.
//! - Release update check against the GitHub releases API.
//! Both run on background threads; the UI never blocks on network.

use sha1::{Digest, Sha1};

use crate::models::ToolkitError;

fn client() -> Result<reqwest::blocking::Client, ToolkitError> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .user_agent("LarvSecurity/0.1.0 (local-first security toolkit)")
        .build()
        .map_err(|e| ToolkitError::Other(format!("network unavailable: {e}")))
}

/// Returns how many times the password appeared in breaches (0 = clean).
pub fn breach_count(password: &str) -> Result<u64, ToolkitError> {
    if password.is_empty() {
        return Err(ToolkitError::InvalidPassword);
    }
    let full = hex::encode(Sha1::digest(password.as_bytes())).to_uppercase();
    let (prefix, suffix) = full.split_at(5);
    let url = format!("https://api.haveibeenpwned.com/range/{prefix}");
    let body = client()?
        .get(&url)
        .send()
        .map_err(|e| ToolkitError::Other(format!("breach lookup failed: {e}")))?
        .error_for_status()
        .map_err(|e| ToolkitError::Other(format!("breach lookup failed: {e}")))?
        .text()
        .map_err(|e| ToolkitError::Other(format!("breach lookup failed: {e}")))?;
    for line in body.lines() {
        let mut it = line.split(':');
        if let (Some(h), Some(n)) = (it.next(), it.next()) {
            if h.trim().eq_ignore_ascii_case(suffix) {
                return Ok(n.trim().parse().unwrap_or(1));
            }
        }
    }
    Ok(0)
}

/// Latest release tag on GitHub, e.g. `v0.1.0`. None if unreachable.
pub fn latest_release_tag() -> Result<String, ToolkitError> {
    let text = client()?
        .get("https://api.github.com/repos/HabbashX/LarvSecurity/releases/latest")
        .send()
        .map_err(|e| ToolkitError::Other(format!("update check failed: {e}")))?
        .error_for_status()
        .map_err(|e| ToolkitError::Other(format!("update check failed: {e}")))?
        .text()
        .map_err(|e| ToolkitError::Other(format!("update check failed: {e}")))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| ToolkitError::Other(format!("update check failed: {e}")))?;
    v.get("tag_name")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| ToolkitError::Other("no releases found".into()))
}
