use serde::{Deserialize, Serialize};

/// Password generator strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PasswordStrategy {
    #[default]
    Random,
    Passphrase,
    Pin,
    Pattern,
}

impl PasswordStrategy {
    pub fn label(self) -> &'static str {
        match self {
            PasswordStrategy::Random => "Random",
            PasswordStrategy::Passphrase => "Passphrase",
            PasswordStrategy::Pin => "PIN",
            PasswordStrategy::Pattern => "Pattern",
        }
    }
}

/// Configuration for the random-password strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomPasswordConfig {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub min_uppercase: usize,
    pub min_lowercase: usize,
    pub min_numbers: usize,
    pub min_symbols: usize,
}

impl Default for RandomPasswordConfig {
    fn default() -> Self {
        Self {
            length: 32,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            min_uppercase: 2,
            min_lowercase: 2,
            min_numbers: 4,
            min_symbols: 4,
        }
    }
}

/// Configuration for passphrase generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseConfig {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub add_number: bool,
    pub add_symbol: bool,
}

impl Default for PassphraseConfig {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".to_string(),
            capitalize: true,
            add_number: true,
            add_symbol: true,
        }
    }
}

/// Configuration for PIN generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinConfig {
    pub length: usize,
}

impl Default for PinConfig {
    fn default() -> Self {
        Self { length: 6 }
    }
}

/// Analysis shown next to every generated password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordAnalysis {
    pub length: usize,
    pub has_upper: bool,
    pub has_lower: bool,
    pub has_digit: bool,
    pub has_symbol: bool,
    pub estimated_entropy_bits: f64,
    pub strength_label: String,
    pub satisfies_policy: bool,
}
