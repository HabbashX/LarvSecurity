//! Central application state. Secrets are cleared on tool switch.

use crate::app::navigation::Tool;
use crate::app::theme::{AccentChoice, ThemeMode};
use crate::models::{
    ArgonParams, CipherAlgorithm, JwtAlgorithm, OutputFormat, PassphraseConfig, PasswordAnalysis,
    PasswordStrategy, PinConfig, RandomPasswordConfig,
};
use crate::utils::clipboard::ClipboardState;
use crate::utils::secure_memory::clear_string;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtTab {
    Generate,
    Decode,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoTab {
    Text,
    File,
}

pub struct AppState {
    pub tool: Tool,
    pub theme: ThemeMode,
    pub motion: bool,
    // appearance
    pub accent: AccentChoice,
    pub corner: u8,
    pub base_size: f32,
    pub mono_ui: bool,
    pub ui_scale: f32,
    pub custom_font_name: Option<String>,
    pub custom_font_bytes: Option<Vec<u8>>,
    pub palette_open: bool,
    pub palette_query: String,
    pub status: Option<String>,
    pub status_is_error: bool,
    pub clipboard: ClipboardState,

    // password
    pub pw_strategy: PasswordStrategy,
    pub pw_random: RandomPasswordConfig,
    pub pw_pass: PassphraseConfig,
    pub pw_pin: PinConfig,
    pub pw_pattern: String,
    pub pw_output: String,
    pub pw_analysis: Option<PasswordAnalysis>,

    // jwt
    pub jwt_tab: JwtTab,
    pub jwt_alg: JwtAlgorithm,
    pub jwt_payload: String,
    pub jwt_key: String,
    pub jwt_key_visible: bool,
    pub jwt_token: String,
    pub jwt_decode_input: String,
    pub jwt_verify_token: String,
    pub jwt_verify_alg: JwtAlgorithm,
    pub jwt_verify_key: String,
    pub jwt_verify_key_visible: bool,
    pub jwt_verify_iss: String,
    pub jwt_verify_aud: String,

    // encryption
    pub enc_tab: CryptoTab,
    pub enc_alg: CipherAlgorithm,
    pub enc_mode_password: bool,
    pub enc_input: String,
    pub enc_password: String,
    pub enc_password_visible: bool,
    pub enc_key_hex: String,
    pub enc_aad: String,
    pub enc_output_format: OutputFormat,
    pub enc_argon: ArgonParams,
    pub enc_output: String,
    pub dec_input: String,
    pub dec_password: String,
    pub dec_password_visible: bool,
    pub dec_key_hex: String,
    pub dec_aad: String,
    pub dec_output: String,
    pub file_input_path: String,
    pub file_output_path: String,
    pub file_busy: bool,
    pub file_progress: String,

    // hashing
    pub hash_input: String,
    pub hash_file_path: String,
    pub kdf_password: String,
    pub kdf_password_visible: bool,
    pub kdf_alg: crate::crypto::hashing::KdfAlgorithm,
    pub kdf_output: String,

    // keys
    pub sym_size: usize,
    pub sym_hex: String,
    pub sym_b64: String,
    pub rsa_bits: usize,
    pub rsa_busy: bool,
    pub rsa_pub: String,
    pub rsa_priv: String,
    pub ec_curve: crate::crypto::keys::EcCurve,
    pub ec_pub: String,
    pub ec_priv: String,

    // encoding
    pub enc_text_input: String,
    pub enc_text_output: String,

    // random
    pub rand_size: String,
    pub rand_output: String,
    pub rand_int_min: String,
    pub rand_int_max: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            tool: Tool::Password,
            theme: ThemeMode::Dark,
            motion: true,
            accent: AccentChoice::Indigo,
            corner: 8,
            base_size: 13.5,
            mono_ui: false,
            ui_scale: 1.0,
            custom_font_name: None,
            custom_font_bytes: None,
            palette_open: false,
            palette_query: String::new(),
            status: None,
            status_is_error: false,
            clipboard: ClipboardState::default(),
            pw_strategy: PasswordStrategy::Random,
            pw_random: RandomPasswordConfig::default(),
            pw_pass: PassphraseConfig::default(),
            pw_pin: PinConfig::default(),
            pw_pattern: "UUU-lll-NNN-SSS".to_string(),
            pw_output: String::new(),
            pw_analysis: None,
            jwt_tab: JwtTab::Generate,
            jwt_alg: JwtAlgorithm::Hs256,
            jwt_payload: "{\n  \"sub\": \"12345\",\n  \"name\": \"John\",\n  \"role\": \"USER\",\n  \"iat\": 1720000000,\n  \"exp\": 1999999999\n}".to_string(),
            jwt_key: String::new(),
            jwt_key_visible: false,
            jwt_token: String::new(),
            jwt_decode_input: String::new(),
            jwt_verify_token: String::new(),
            jwt_verify_alg: JwtAlgorithm::Hs256,
            jwt_verify_key: String::new(),
            jwt_verify_key_visible: false,
            jwt_verify_iss: String::new(),
            jwt_verify_aud: String::new(),
            enc_tab: CryptoTab::Text,
            enc_alg: CipherAlgorithm::Aes256Gcm,
            enc_mode_password: true,
            enc_input: String::new(),
            enc_password: String::new(),
            enc_password_visible: false,
            enc_key_hex: String::new(),
            enc_aad: String::new(),
            enc_output_format: OutputFormat::EnvelopeJson,
            enc_argon: ArgonParams::default(),
            enc_output: String::new(),
            dec_input: String::new(),
            dec_password: String::new(),
            dec_password_visible: false,
            dec_key_hex: String::new(),
            dec_aad: String::new(),
            dec_output: String::new(),
            file_input_path: String::new(),
            file_output_path: String::new(),
            file_busy: false,
            file_progress: String::new(),
            hash_input: String::new(),
            hash_file_path: String::new(),
            kdf_password: String::new(),
            kdf_password_visible: false,
            kdf_alg: crate::crypto::hashing::KdfAlgorithm::Argon2id,
            kdf_output: String::new(),
            sym_size: 32,
            sym_hex: String::new(),
            sym_b64: String::new(),
            rsa_bits: 2048,
            rsa_busy: false,
            rsa_pub: String::new(),
            rsa_priv: String::new(),
            ec_curve: crate::crypto::keys::EcCurve::P256,
            ec_pub: String::new(),
            ec_priv: String::new(),
            enc_text_input: String::new(),
            enc_text_output: String::new(),
            rand_size: "32".to_string(),
            rand_output: String::new(),
            rand_int_min: "1".to_string(),
            rand_int_max: "100".to_string(),
        }
    }
}

impl AppState {
    pub fn set_status(&mut self, ok: bool, msg: impl Into<String>) {
        self.status = Some(msg.into());
        self.status_is_error = !ok;
    }

    pub fn clear_status(&mut self) {
        self.status = None;
        self.status_is_error = false;
    }

    /// Switch tool and clear sensitive buffers from the previous tool.
    pub fn switch_tool(&mut self, tool: Tool) {
        // Best-effort clearing of secrets; see secure_memory docs.
        clear_string(&mut self.jwt_key);
        clear_string(&mut self.jwt_verify_key);
        clear_string(&mut self.enc_password);
        clear_string(&mut self.dec_password);
        clear_string(&mut self.kdf_password);
        self.jwt_key_visible = false;
        self.jwt_verify_key_visible = false;
        self.enc_password_visible = false;
        self.dec_password_visible = false;
        self.kdf_password_visible = false;
        // Private keys are kept only until the user navigates away from keys.
        if self.tool == Tool::Keys && tool != Tool::Keys {
            clear_string(&mut self.rsa_priv);
            clear_string(&mut self.ec_priv);
        }
        self.tool = tool;
        self.clear_status();
        match tool {
            Tool::JwtGenerate => self.jwt_tab = JwtTab::Generate,
            Tool::JwtDecode => self.jwt_tab = JwtTab::Decode,
            Tool::JwtVerify => self.jwt_tab = JwtTab::Verify,
            _ => {}
        }
    }
}
