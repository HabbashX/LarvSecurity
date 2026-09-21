//! Input validation helpers (never panic on user input).

pub fn parse_usize(s: &str, field: &str, min: usize, max: usize) -> Result<usize, String> {
    let v: usize = s
        .trim()
        .parse()
        .map_err(|_| format!("{field} must be a number between {min} and {max}"))?;
    if v < min || v > max {
        return Err(format!("{field} must be between {min} and {max}"));
    }
    Ok(v)
}

pub fn parse_i64(s: &str, field: &str) -> Result<i64, String> {
    s.trim()
        .parse()
        .map_err(|_| format!("{field} must be an integer"))
}

pub fn require_nonempty(s: &str, field: &str) -> Result<(), String> {
    if s.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

pub fn is_valid_json_object(s: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(s).map(|v| v.is_object()).unwrap_or(false)
}
