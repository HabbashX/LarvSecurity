//! Minimal EN/AR dictionary for chrome + navigation.
//! Tool-page bodies stay English for now; sidebar, top bar, palette,
//! and common actions are translated. Layout remains LTR.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    #[default]
    English,
    Arabic,
}

impl Language {
    pub fn label(self) -> &'static str {
        match self {
            Language::English => "English",
            Language::Arabic => "العربية",
        }
    }
    pub fn all() -> &'static [Language] {
        &[Language::English, Language::Arabic]
    }
}

/// Translate a UI key. Unknown keys fall back to the key itself.
pub fn t(lang: Language, key: &str) -> &str {
    if lang == Language::English {
        return key;
    }
    match key {
        // Sections
        "PASSWORD" => "كلمات المرور",
        "JWT" => "JWT",
        "CRYPTOGRAPHY" => "التشفير",
        "UTILITIES" => "أدوات",
        "AUTH" => "المصادقة",
        "FILES" => "الملفات",
        "DEV" => "المطوّر",
        "SIGNING" => "التوقيع",
        "SETTINGS" => "الإعدادات",
        "ABOUT" => "حول",
        // Tools
        "Password Generator" => "مولّد كلمات المرور",
        "JWT Generator" => "مولّد JWT",
        "JWT Decoder" => "فاكّ JWT",
        "JWT Verifier" => "التحقق من JWT",
        "Encrypt / Decrypt" => "تشفير / فك تشفير",
        "Hash Generator" => "مولّد البصمات",
        "Key Generator" => "مولّد المفاتيح",
        "Encoding" => "الترميز",
        "Random Generator" => "مولّد العشوائية",
        "Authenticator" => "المصادقة (TOTP)",
        "Vault" => "الخزنة",
        "Checksums" => "البصمات الجماعية",
        "File Shredder" => "ممزّق الملفات",
        "JSON Tools" => "أدوات JSON",
        "Time & Cron" => "الوقت و Cron",
        "Regex Tester" => "فاحص Regex",
        "Diff Viewer" => "عارض الفروقات",
        "QR Codes" => "رموز QR",
        "Signatures" => "التواقيع",
        "HMAC" => "HMAC",
        "Certificates" => "الشهادات",
        "SSH Keys" => "مفاتيح SSH",
        "Activity" => "السجل",
        "Appearance" => "المظهر",
        "About" => "حول",
        // Chrome
        "Security Toolkit" => "عدّة الأمان",
        "Tools (Ctrl+K)" => "الأدوات (Ctrl+K)",
        "Ready." => "جاهز.",
        "Search tools" => "ابحث في الأدوات",
        "OFFLINE" => "دون اتصال",
        "LOCAL" => "محلّي",
        // Common actions
        "Generate" => "ولّد",
        "Copy" => "انسخ",
        "Clear" => "امسح",
        "Encrypt" => "شفّر",
        "Decrypt" => "فكّ التشفير",
        "Verify" => "تحقق",
        "Hash" => "احسب",
        "Convert" => "حوّل",
        "Save" => "احفظ",
        "Lock" => "اقفل",
        "Unlock" => "افتح",
        "Clipboard clear:" => "مسح الحافظة:",
        _ => key,
    }
}
