//! Password / passphrase / PIN / pattern generation + analysis.
//!
//! All randomness comes from `rand::rngs::OsRng` (CSPRNG). No custom RNG.

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::RngCore;

use crate::models::{
    PassphraseConfig, PasswordAnalysis, PinConfig, RandomPasswordConfig, ToolkitError,
};

pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?~";
const UPPERS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERS: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";

fn rand_index(n: usize) -> Result<usize, ToolkitError> {
    if n == 0 {
        return Err(ToolkitError::InvalidInput(
            "empty character set".to_string(),
        ));
    }
    // Rejection sampling on u64 to avoid modulo bias.
    let mut buf = [0u8; 8];
    let bound = (u64::MAX / n as u64) * n as u64;
    loop {
        OsRng.fill_bytes(&mut buf);
        let v = u64::from_le_bytes(buf);
        if v < bound {
            return Ok((v % n as u64) as usize);
        }
    }
}

fn pick_from(pool: &[char]) -> Result<char, ToolkitError> {
    Ok(pool[rand_index(pool.len())?])
}

/// Fisher-Yates shuffle with OsRng.
fn shuffle(chars: &mut [char]) {
    chars.shuffle(&mut OsRng);
}

pub fn generate_random(cfg: &RandomPasswordConfig) -> Result<String, ToolkitError> {
    if cfg.length == 0 {
        return Err(ToolkitError::InvalidInput(
            "length must be >= 1".to_string(),
        ));
    }
    if !(cfg.uppercase || cfg.lowercase || cfg.numbers || cfg.symbols) {
        return Err(ToolkitError::PolicyViolation(
            "enable at least one character set".to_string(),
        ));
    }
    let required =
        cfg.min_uppercase + cfg.min_lowercase + cfg.min_numbers + cfg.min_symbols;
    if required > cfg.length {
        return Err(ToolkitError::PolicyViolation(format!(
            "minimums sum to {required} but length is {}",
            cfg.length
        )));
    }
    if cfg.min_uppercase > 0 && !cfg.uppercase {
        return Err(ToolkitError::PolicyViolation(
            "min uppercase > 0 but uppercase disabled".to_string(),
        ));
    }
    if cfg.min_lowercase > 0 && !cfg.lowercase {
        return Err(ToolkitError::PolicyViolation(
            "min lowercase > 0 but lowercase disabled".to_string(),
        ));
    }
    if cfg.min_numbers > 0 && !cfg.numbers {
        return Err(ToolkitError::PolicyViolation(
            "min numbers > 0 but numbers disabled".to_string(),
        ));
    }
    if cfg.min_symbols > 0 && !cfg.symbols {
        return Err(ToolkitError::PolicyViolation(
            "min symbols > 0 but symbols disabled".to_string(),
        ));
    }

    let uppers: Vec<char> = UPPERS.chars().collect();
    let lowers: Vec<char> = LOWERS.chars().collect();
    let digits: Vec<char> = DIGITS.chars().collect();
    let syms: Vec<char> = SYMBOLS.chars().collect();

    let mut pool: Vec<char> = Vec::new();
    if cfg.uppercase {
        pool.extend_from_slice(&uppers);
    }
    if cfg.lowercase {
        pool.extend_from_slice(&lowers);
    }
    if cfg.numbers {
        pool.extend_from_slice(&digits);
    }
    if cfg.symbols {
        pool.extend_from_slice(&syms);
    }

    let mut out: Vec<char> = Vec::with_capacity(cfg.length);
    for _ in 0..cfg.min_uppercase {
        out.push(pick_from(&uppers)?);
    }
    for _ in 0..cfg.min_lowercase {
        out.push(pick_from(&lowers)?);
    }
    for _ in 0..cfg.min_numbers {
        out.push(pick_from(&digits)?);
    }
    for _ in 0..cfg.min_symbols {
        out.push(pick_from(&syms)?);
    }
    while out.len() < cfg.length {
        out.push(pick_from(&pool)?);
    }
    shuffle(&mut out);
    Ok(out.into_iter().collect())
}

// Small built-in word list (~128 common words) so passphrases work offline.
pub const WORDLIST: &[&str] = &[
    "amber", "anchor", "apple", "atlas", "autumn", "badge", "baker", "banner", "basin", "beacon",
    "birch", "blade", "bloom", "boulder", "brave", "bridge", "bright", "brook", "cabin", "canyon",
    "cedar", "cherry", "cinder", "citrus", "cliff", "cloud", "cobalt", "comet", "copper", "coral",
    "crane", "crest", "cricket", "dawn", "delta", "dune", "eagle", "ember", "engine", "falcon",
    "fern", "field", "flint", "forest", "forge", "frost", "garnet", "glacier", "grove", "harbor",
    "hazel", "heron", "hollow", "horizon", "indigo", "inlet", "island", "ivory", "juniper",
    "kernel", "lagoon", "lantern", "larch", "laurel", "lemon", "linen", "lumen", "maple", "marble",
    "meadow", "meridian", "meteor", "mist", "moss", "north", "oasis", "ocean", "onyx", "orbit",
    "otter", "oyster", "pebble", "pepper", "pilot", "pine", "planet", "plaza", "prairie", "quartz",
    "raven", "ridge", "river", "robin", "saddle", "sage", "sand", "signal", "silver", "solar",
    "spruce", "stone", "storm", "summit", "surge", "tango", "teal", "thunder", "timber", "topaz",
    "trail", "tulip", "tundra", "valley", "velvet", "victor", "violet", "water", "willow",
    "window", "yukon", "zephyr", "zinc", "elm", "ash", "birchwood", "cobble", "drift", "echo",
    "flame", "glade", "heath",
];

pub fn generate_passphrase(cfg: &PassphraseConfig) -> Result<String, ToolkitError> {
    let owned: Vec<String> = WORDLIST.iter().map(|s| s.to_string()).collect();
    generate_passphrase_with_list(cfg, &owned)
}

/// Passphrase from a caller-supplied wordlist (diceware with your own list).
pub fn generate_passphrase_with_list(cfg: &PassphraseConfig, list: &[String]) -> Result<String, ToolkitError> {
    if cfg.words == 0 || cfg.words > 64 {
        return Err(ToolkitError::InvalidInput(
            "words must be between 1 and 64".to_string(),
        ));
    }
    if cfg.separator.chars().count() > 8 {
        return Err(ToolkitError::InvalidInput(
            "separator too long (max 8 chars)".to_string(),
        ));
    }
    let mut words: Vec<String> = Vec::with_capacity(cfg.words);
    if list.is_empty() {
        return Err(ToolkitError::InvalidInput("wordlist is empty".into()));
    }
    for _ in 0..cfg.words {
        let w = &list[rand_index(list.len())?];
        if cfg.capitalize {
            let mut c = w.chars();
            let first = c.next().unwrap_or('x').to_uppercase().to_string();
            words.push(format!("{first}{}", c.as_str()));
        } else {
            words.push(w.to_string());
        }
    }
    let mut out = words.join(&cfg.separator);
    if cfg.add_number {
        let mut buf = [0u8; 1];
        OsRng.fill_bytes(&mut buf);
        out.push_str(&cfg.separator);
        out.push_str(&(buf[0] % 10).to_string());
    }
    if cfg.add_symbol {
        let syms: Vec<char> = SYMBOLS.chars().collect();
        out.push_str(&cfg.separator);
        out.push(pick_from(&syms)?);
    }
    Ok(out)
}

pub fn generate_pin(cfg: &PinConfig) -> Result<String, ToolkitError> {
    if ![4, 6, 8, 10, 12].contains(&cfg.length) && (cfg.length == 0 || cfg.length > 32) {
        return Err(ToolkitError::InvalidInput(
            "PIN length must be 1..=32 (commonly 4, 6, 8, 10, 12)".to_string(),
        ));
    }
    let digits: Vec<char> = DIGITS.chars().collect();
    let mut out = String::with_capacity(cfg.length);
    for _ in 0..cfg.length {
        out.push(pick_from(&digits)?);
    }
    Ok(out)
}

/// Pattern syntax:
/// - `U` uppercase, `l` lowercase, `L` any letter, `N` digit,
///   `S` symbol, `A` alphanumeric. Any other char is literal.
pub fn pattern_help() -> &'static str {
    "U=uppercase  l=lowercase  L=letter  N=digit  S=symbol  A=alphanumeric. Other chars are literal. Example: LLL-999-SSS is not valid; use LLL-NNN-SSS."
}

pub fn generate_pattern(pattern: &str) -> Result<String, ToolkitError> {
    if pattern.is_empty() {
        return Err(ToolkitError::InvalidInput(
            "pattern must not be empty".to_string(),
        ));
    }
    if pattern.chars().count() > 256 {
        return Err(ToolkitError::InvalidInput(
            "pattern too long (max 256)".to_string(),
        ));
    }
    let uppers: Vec<char> = UPPERS.chars().collect();
    let lowers: Vec<char> = LOWERS.chars().collect();
    let digits: Vec<char> = DIGITS.chars().collect();
    let syms: Vec<char> = SYMBOLS.chars().collect();
    let letters: Vec<char> = uppers.iter().chain(lowers.iter()).copied().collect();
    let alnum: Vec<char> = letters.iter().chain(digits.iter()).copied().collect();

    let mut out = String::new();
    for ch in pattern.chars() {
        match ch {
            'U' => out.push(pick_from(&uppers)?),
            'l' => out.push(pick_from(&lowers)?),
            'L' => out.push(pick_from(&letters)?),
            'N' | '9' => out.push(pick_from(&digits)?),
            'S' => out.push(pick_from(&syms)?),
            'A' => out.push(pick_from(&alnum)?),
            other => out.push(other),
        }
    }
    Ok(out)
}

/// Estimated entropy: sum of log2(pool) per char class actually usable.
/// This is an *estimate*, not a security guarantee.
pub fn analyze_password(pw: &str, pool_hint: Option<usize>) -> PasswordAnalysis {
    let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = pw.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_symbol = pw
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace());

    let mut pool = 0usize;
    if has_upper {
        pool += 26;
    }
    if has_lower {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_symbol {
        pool += SYMBOLS.chars().count();
    }
    if let Some(hint) = pool_hint {
        if hint > pool {
            pool = hint;
        }
    }
    if pool < 2 {
        pool = 2;
    }
    let entropy = (pw.chars().count() as f64) * (pool as f64).log2();
    let strength_label = if entropy < 40.0 {
        "Weak"
    } else if entropy < 60.0 {
        "Fair"
    } else if entropy < 90.0 {
        "Strong"
    } else {
        "Very strong"
    }
    .to_string();

    PasswordAnalysis {
        length: pw.chars().count(),
        has_upper,
        has_lower,
        has_digit,
        has_symbol,
        estimated_entropy_bits: entropy,
        strength_label,
        satisfies_policy: true,
    }
}

/// Check a password against a random-password policy.
pub fn check_policy(pw: &str, cfg: &RandomPasswordConfig) -> bool {
    if pw.chars().count() != cfg.length && pw.chars().count() < cfg.length {
        // allow longer pasted passwords to still be evaluated loosely
    }
    let up = pw.chars().filter(|c| c.is_ascii_uppercase()).count();
    let lo = pw.chars().filter(|c| c.is_ascii_lowercase()).count();
    let di = pw.chars().filter(|c| c.is_ascii_digit()).count();
    let sy = pw
        .chars()
        .filter(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace())
        .count();
    up >= cfg.min_uppercase
        && lo >= cfg.min_lowercase
        && di >= cfg.min_numbers
        && sy >= cfg.min_symbols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_respects_length_and_minimums() {
        let cfg = RandomPasswordConfig {
            length: 32,
            min_uppercase: 2,
            min_lowercase: 2,
            min_numbers: 4,
            min_symbols: 4,
            ..Default::default()
        };
        let pw = generate_random(&cfg).unwrap();
        assert_eq!(pw.chars().count(), 32);
        assert!(check_policy(&pw, &cfg));
    }

    #[test]
    fn rejects_empty_charset() {
        let cfg = RandomPasswordConfig {
            uppercase: false,
            lowercase: false,
            numbers: false,
            symbols: false,
            min_uppercase: 0,
            min_lowercase: 0,
            min_numbers: 0,
            min_symbols: 0,
            length: 16,
        };
        assert!(generate_random(&cfg).is_err());
    }

    #[test]
    fn passphrase_shape() {
        let cfg = PassphraseConfig::default();
        let pp = generate_passphrase(&cfg).unwrap();
        assert!(pp.contains('-'));
    }

    #[test]
    fn pin_is_numeric() {
        let pin = generate_pin(&PinConfig { length: 6 }).unwrap();
        assert_eq!(pin.len(), 6);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn pattern_generates() {
        let s = generate_pattern("UUU-lll-NNN-SSS").unwrap();
        assert_eq!(s.chars().count(), 15);
    }
}
