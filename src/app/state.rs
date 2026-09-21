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
    Jwe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoTab {
    Text,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PwTab {
    #[default]
    Generate,
    Strength,
    Bulk,
    Breach,
}

impl PwTab {
    pub fn label(self) -> &'static str {
        match self {
            PwTab::Generate => "Generate",
            PwTab::Strength => "Strength",
            PwTab::Bulk => "Bulk",
            PwTab::Breach => "Breach check",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub ts: String,
    pub tool: String,
    pub action: String,
}

#[derive(Debug, Clone)]
pub struct TotpAccount {
    pub name: String,
    pub secret_b32: String,
    pub hash: crate::crypto::totp::TotpHash,
    pub digits: u32,
    pub step: u64,
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

    // chrome / prefs
    pub lang: crate::utils::i18n::Language,
    pub favorites: Vec<String>,
    pub recents: Vec<String>,
    pub history: Vec<HistoryEntry>,
    pub session_start: std::time::Instant,

    // password tabs
    pub pw_tab: PwTab,
    pub pw_custom_list: String,
    pub pw_use_custom_list: bool,
    pub strength_input: String,
    pub bulk_count: String,
    pub bulk_len: String,
    pub bulk_output: String,
    pub breach_opt_in: bool,
    pub breach_password: String,
    pub breach_password_visible: bool,
    pub breach_result: String,
    pub breach_busy: bool,

    // jwt extras
    pub jwt_presets: Vec<crate::utils::config::JwtPreset>,
    pub jwt_preset_name: String,
    pub jwt_history: Vec<String>,
    pub jwe_payload: String,
    pub jwe_key: String,
    pub jwe_key_visible: bool,
    pub jwe_output: String,
    pub snippet_lang: String,

    // totp
    pub totp_accounts: Vec<TotpAccount>,
    pub totp_name: String,
    pub totp_secret: String,
    pub totp_secret_visible: bool,
    pub totp_hash: crate::crypto::totp::TotpHash,
    pub totp_digits: u32,
    pub totp_step: String,
    pub totp_probe: String,
    pub totp_probe_result: String,

    // vault
    pub vault_unlocked: bool,
    pub vault_entries: Vec<crate::crypto::vault::VaultEntry>,
    pub vault_master: String,
    pub vault_master_visible: bool,
    pub vault_lock_minutes: String,
    pub vault_lock_at: Option<std::time::Instant>,
    pub vault_new_service: String,
    pub vault_new_user: String,
    pub vault_new_secret: String,
    pub vault_new_secret_visible: bool,
    pub vault_new_notes: String,
    pub vault_file_text: String,

    // checksums + shredder
    pub cs_root: String,
    pub cs_manifest: String,
    pub cs_report: String,
    pub sh_path: String,
    pub sh_passes: crate::crypto::shred::ShredPasses,
    pub sh_status: String,
    pub sh_done: u64,
    pub sh_total: u64,

    // dev tools
    pub json_input: String,
    pub json_output: String,
    pub json_sort_keys: bool,
    pub ts_input: String,
    pub ts_output: String,
    pub cron_expr: String,
    pub cron_output: String,
    pub rx_pattern: String,
    pub rx_text: String,
    pub rx_insensitive: bool,
    pub rx_output: String,
    pub diff_a: String,
    pub diff_b: String,
    pub qr_text: String,
    pub qr_unicode: String,
    pub qr_svg: String,
    pub wifi_ssid: String,
    pub wifi_pass: String,
    pub wifi_enc: String,

    // signatures + hmac
    pub sig_scheme: crate::crypto::sigs::SigScheme,
    pub sig_priv: String,
    pub sig_priv_visible: bool,
    pub sig_pub: String,
    pub sig_text: String,
    pub sig_file: String,
    pub sig_out_b64: String,
    pub sig_result: String,
    pub hmac_hash: crate::crypto::sigs::HmacHash,
    pub hmac_key: String,
    pub hmac_key_visible: bool,
    pub hmac_msg: String,
    pub hmac_out: String,
    pub hmac_expect: String,
    pub hmac_result: String,

    // certs + ssh
    pub cert_input: String,
    pub cert_details: String,
    pub cert_warnings: String,
    pub ssh_kind: String,
    pub ssh_bits: usize,
    pub ssh_comment: String,
    pub ssh_priv: String,
    pub ssh_pub: String,
    pub ssh_fp: String,
    pub ssh_inspect: String,
    pub ssh_inspect_out: String,

    // update checker
    pub update_opt_in: bool,
    pub update_status: String,
    pub update_busy: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            tool: Tool::Password,
            theme: ThemeMode::Dark,
            motion: true,
            accent: AccentChoice::Sage,
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
            lang: crate::utils::i18n::Language::English,
            favorites: Vec::new(),
            recents: Vec::new(),
            history: Vec::new(),
            session_start: std::time::Instant::now(),
            pw_tab: PwTab::Generate,
            pw_custom_list: String::new(),
            pw_use_custom_list: false,
            strength_input: String::new(),
            bulk_count: "20".to_string(),
            bulk_len: "24".to_string(),
            bulk_output: String::new(),
            breach_opt_in: false,
            breach_password: String::new(),
            breach_password_visible: false,
            breach_result: String::new(),
            breach_busy: false,
            jwt_presets: Vec::new(),
            jwt_preset_name: String::new(),
            jwt_history: Vec::new(),
            jwe_payload: "{\n  \"sub\": \"12345\",\n  \"role\": \"USER\"\n}".to_string(),
            jwe_key: String::new(),
            jwe_key_visible: false,
            jwe_output: String::new(),
            snippet_lang: "cURL".to_string(),
            totp_accounts: Vec::new(),
            totp_name: String::new(),
            totp_secret: String::new(),
            totp_secret_visible: false,
            totp_hash: crate::crypto::totp::TotpHash::Sha1,
            totp_digits: 6,
            totp_step: "30".to_string(),
            totp_probe: String::new(),
            totp_probe_result: String::new(),
            vault_unlocked: false,
            vault_entries: Vec::new(),
            vault_master: String::new(),
            vault_master_visible: false,
            vault_lock_minutes: "15".to_string(),
            vault_lock_at: None,
            vault_new_service: String::new(),
            vault_new_user: String::new(),
            vault_new_secret: String::new(),
            vault_new_secret_visible: false,
            vault_new_notes: String::new(),
            vault_file_text: String::new(),
            cs_root: String::new(),
            cs_manifest: String::new(),
            cs_report: String::new(),
            sh_path: String::new(),
            sh_passes: crate::crypto::shred::ShredPasses::Three,
            sh_status: String::new(),
            sh_done: 0,
            sh_total: 1,
            json_input: "{\n  \"name\": \"ada\",\n  \"roles\": [\"admin\", \"dev\"]\n}".to_string(),
            json_output: String::new(),
            json_sort_keys: false,
            ts_input: String::new(),
            ts_output: String::new(),
            cron_expr: "0 9 * * mon-fri".to_string(),
            cron_output: String::new(),
            rx_pattern: String::new(),
            rx_text: String::new(),
            rx_insensitive: false,
            rx_output: String::new(),
            diff_a: String::new(),
            diff_b: String::new(),
            qr_text: String::new(),
            qr_unicode: String::new(),
            qr_svg: String::new(),
            wifi_ssid: String::new(),
            wifi_pass: String::new(),
            wifi_enc: "WPA".to_string(),
            sig_scheme: crate::crypto::sigs::SigScheme::RsaPkcs1Sha256,
            sig_priv: String::new(),
            sig_priv_visible: false,
            sig_pub: String::new(),
            sig_text: String::new(),
            sig_file: String::new(),
            sig_out_b64: String::new(),
            sig_result: String::new(),
            hmac_hash: crate::crypto::sigs::HmacHash::Sha256,
            hmac_key: String::new(),
            hmac_key_visible: false,
            hmac_msg: String::new(),
            hmac_out: String::new(),
            hmac_expect: String::new(),
            hmac_result: String::new(),
            cert_input: String::new(),
            cert_details: String::new(),
            cert_warnings: String::new(),
            ssh_kind: "ed25519".to_string(),
            ssh_bits: 3072,
            ssh_comment: String::new(),
            ssh_priv: String::new(),
            ssh_pub: String::new(),
            ssh_fp: String::new(),
            ssh_inspect: String::new(),
            ssh_inspect_out: String::new(),
            update_opt_in: false,
            update_status: String::new(),
            update_busy: false,
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

    /// Apply a loaded workspace (appearance + lists; never secrets).
    pub fn apply_workspace(&mut self, ws: &crate::utils::config::WorkspaceData) {
        use crate::app::theme::{AccentChoice, ThemeMode};
        use crate::utils::i18n::Language;
        self.theme = match ws.theme.as_str() {
            "Light" => ThemeMode::Light,
            "System" => ThemeMode::System,
            _ => ThemeMode::Dark,
        };
        self.accent = AccentChoice::all()
            .iter()
            .find(|a| a.label() == ws.accent)
            .copied()
            .unwrap_or(AccentChoice::Sage);
        self.base_size = ws.base_size.clamp(11.0, 17.0);
        self.mono_ui = ws.mono_ui;
        self.ui_scale = ws.ui_scale.clamp(0.8, 1.5);
        self.corner = ws.corner.min(14);
        self.motion = ws.motion;
        self.lang = if ws.language == "العربية" || ws.language.eq_ignore_ascii_case("arabic") {
            Language::Arabic
        } else {
            Language::English
        };
        self.clipboard.auto_clear_secs = ws.clipboard_secs.clamp(5, 600);
        self.favorites = ws
            .favorites
            .iter()
            .filter(|t| Tool::from_title(t).is_some())
            .cloned()
            .collect();
        self.recents = ws.recents.clone();
        self.jwt_presets = ws.jwt_presets.clone();
    }

    /// Snapshot current workspace for saving (never includes secrets).
    pub fn snapshot_workspace(&self) -> crate::utils::config::WorkspaceData {
        crate::utils::config::WorkspaceData {
            version: 1,
            theme: self.theme.label().to_string(),
            accent: self.accent.label().to_string(),
            base_size: self.base_size,
            mono_ui: self.mono_ui,
            ui_scale: self.ui_scale,
            corner: self.corner,
            motion: self.motion,
            language: self.lang.label().to_string(),
            clipboard_secs: self.clipboard.auto_clear_secs,
            favorites: self.favorites.clone(),
            recents: self.recents.clone(),
            jwt_presets: self.jwt_presets.clone(),
        }
    }
    pub fn log(&mut self, tool: &str, action: impl Into<String>) {
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        self.history.push(HistoryEntry {
            ts,
            tool: tool.to_string(),
            action: action.into(),
        });
        if self.history.len() > 300 {
            let excess = self.history.len() - 300;
            self.history.drain(0..excess);
        }
    }

    /// Push a file path onto the recents list (max 10, deduped).
    pub fn touch_recent(path: &mut Vec<String>, p: &str) {
        let p = p.to_string();
        path.retain(|x| x != &p);
        path.insert(0, p);
        path.truncate(10);
    }

    /// Switch tool and clear sensitive buffers from the previous tool.
    pub fn switch_tool(&mut self, tool: Tool) {
        // Best-effort clearing of secrets; see secure_memory docs.
        clear_string(&mut self.jwt_key);
        clear_string(&mut self.jwt_verify_key);
        clear_string(&mut self.enc_password);
        clear_string(&mut self.dec_password);
        clear_string(&mut self.kdf_password);
        clear_string(&mut self.breach_password);
        clear_string(&mut self.hmac_key);
        clear_string(&mut self.sig_priv);
        clear_string(&mut self.totp_secret);
        clear_string(&mut self.vault_new_secret);
        self.jwt_key_visible = false;
        self.jwt_verify_key_visible = false;
        self.enc_password_visible = false;
        self.dec_password_visible = false;
        self.kdf_password_visible = false;
        self.breach_password_visible = false;
        self.hmac_key_visible = false;
        self.sig_priv_visible = false;
        self.totp_secret_visible = false;
        self.vault_new_secret_visible = false;
        // Private keys are kept only until the user navigates away from keys.
        if self.tool == Tool::Keys && tool != Tool::Keys {
            clear_string(&mut self.rsa_priv);
            clear_string(&mut self.ec_priv);
        }
        if self.tool == Tool::SshKeys && tool != Tool::SshKeys {
            clear_string(&mut self.ssh_priv);
        }
        // Leaving the vault view does NOT lock it (auto-lock timer owns that).
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
