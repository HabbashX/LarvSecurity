//! X.509 certificate inspector (read-only).
//! Accepts PEM (`-----BEGIN CERTIFICATE-----`) or raw DER/base64,
//! reports subject, issuer, validity window, SANs, key algorithm,
//! serial, and expiry warnings. Never trusts — inspection only.

use x509_parser::prelude::*;

use base64::Engine as _;

use crate::models::ToolkitError;

#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub public_key_algo: String,
    pub signature_algo: String,
    pub san_list: Vec<String>,
    pub warnings: Vec<String>,
}

fn pem_to_der(input: &str) -> Result<Vec<u8>, ToolkitError> {
    let t = input.trim();
    if t.contains("BEGIN CERTIFICATE") {
        let body: String = t
            .lines()
            .filter(|l| !l.trim().starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .map_err(|_| ToolkitError::InvalidBase64)
    } else if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(t.replace(|c: char| c.is_whitespace(), "")) {
        Ok(b)
    } else {
        Err(ToolkitError::InvalidInput("paste a PEM certificate or base64 DER".into()))
    }
}

pub fn inspect_cert(input: &str) -> Result<CertInfo, ToolkitError> {
    let der = pem_to_der(input)?;
    let (_, cert) = parse_x509_certificate(&der)
        .map_err(|_| ToolkitError::InvalidInput("could not parse X.509 certificate".into()))?;
    let tbs = &cert.tbs_certificate;

    let san_list: Vec<String> = cert
        .subject_alternative_name()
        .map_err(|_| ToolkitError::InvalidInput("bad SAN extension".into()))?
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .map(|n| format!("{n:?}"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let not_after_secs = tbs.validity.not_after.timestamp();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut warnings = Vec::new();
    if not_after_secs <= now_secs {
        warnings.push("Certificate is EXPIRED.".into());
    } else if not_after_secs - now_secs < 30 * 86400 {
        warnings.push("Certificate expires within 30 days.".into());
    }
    if tbs.validity.not_before.timestamp() > now_secs {
        warnings.push("Certificate is not yet valid.".into());
    }
    if san_list.is_empty() {
        warnings.push("No Subject Alternative Names present.".into());
    }

    Ok(CertInfo {
        subject: tbs.subject.to_string(),
        issuer: tbs.issuer.to_string(),
        serial_hex: format!("{:?}", tbs.serial),
        not_before: rfc3339(tbs.validity.not_before.timestamp()),
        not_after: rfc3339(not_after_secs),
        public_key_algo: format!("{:?}", tbs.subject_pki.algorithm.algorithm),
        signature_algo: format!("{:?}", cert.signature_algorithm.algorithm),
        san_list,
        warnings,
    })
}

fn rfc3339(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| format!("epoch+{ts}s"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_rejected_without_panic() {
        assert!(inspect_cert("not a cert").is_err());
        assert!(inspect_cert("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----").is_err());
        assert!(inspect_cert("").is_err());
    }
}
