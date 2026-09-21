#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tool {
    Password,
    JwtGenerate,
    JwtDecode,
    JwtVerify,
    Encrypt,
    Hash,
    Keys,
    Encoding,
    Random,
    Totp,
    Vault,
    Checksums,
    Shredder,
    JsonTools,
    TimeCron,
    RegexTester,
    DiffViewer,
    QrCodes,
    Signatures,
    Hmac,
    Certificates,
    SshKeys,
    Activity,
    Appearance,
    About,
}

impl Tool {
    pub fn title(self) -> &'static str {
        match self {
            Tool::Password => "Password Generator",
            Tool::JwtGenerate => "JWT Generator",
            Tool::JwtDecode => "JWT Decoder",
            Tool::JwtVerify => "JWT Verifier",
            Tool::Encrypt => "Encrypt / Decrypt",
            Tool::Hash => "Hash Generator",
            Tool::Keys => "Key Generator",
            Tool::Encoding => "Encoding",
            Tool::Random => "Random Generator",
            Tool::Totp => "Authenticator",
            Tool::Vault => "Vault",
            Tool::Checksums => "Checksums",
            Tool::Shredder => "File Shredder",
            Tool::JsonTools => "JSON Tools",
            Tool::TimeCron => "Time & Cron",
            Tool::RegexTester => "Regex Tester",
            Tool::DiffViewer => "Diff Viewer",
            Tool::QrCodes => "QR Codes",
            Tool::Signatures => "Signatures",
            Tool::Hmac => "HMAC",
            Tool::Certificates => "Certificates",
            Tool::SshKeys => "SSH Keys",
            Tool::Activity => "Activity",
            Tool::Appearance => "Appearance",
            Tool::About => "About",
        }
    }

    pub fn from_title(s: &str) -> Option<Tool> {
        Self::all().iter().find(|t| t.title() == s).copied()
    }

    pub fn keywords(self) -> &'static str {
        match self {
            Tool::Password => "password passphrase pin pattern entropy generator strength breach bulk diceware",
            Tool::JwtGenerate => "jwt json web token generate sign jws hs256 rs256 es256 jwe preset snippet",
            Tool::JwtDecode => "jwt decode inspect header payload signature base64",
            Tool::JwtVerify => "jwt verify signature exp nbf iss aud",
            Tool::Encrypt => "encrypt decrypt aes gcm chacha argon2 file password key",
            Tool::Hash => "hash sha blake argon pbkdf scrypt kdf file checksum",
            Tool::Keys => "key rsa ec p256 aes chacha generate pem",
            Tool::Encoding => "encoding base64 hex url decode encode",
            Tool::Random => "random bytes uuid token integer csprng",
            Tool::Totp => "totp hotp 2fa authenticator otp qr sha1",
            Tool::Vault => "vault secrets password manager notes autolock aes",
            Tool::Checksums => "checksum manifest folder verify sha256 integrity",
            Tool::Shredder => "shred delete wipe secure erase file",
            Tool::JsonTools => "json format pretty minify validate",
            Tool::TimeCron => "timestamp epoch cron schedule converter",
            Tool::RegexTester => "regex tester match groups pattern",
            Tool::DiffViewer => "diff compare text lines",
            Tool::QrCodes => "qr code generator wifi totp svg",
            Tool::Signatures => "sign verify rsa ecdsa file signature",
            Tool::Hmac => "hmac sha256 authenticate message",
            Tool::Certificates => "x509 certificate tls expiry san inspect",
            Tool::SshKeys => "ssh ed25519 rsa authorized_keys fingerprint",
            Tool::Activity => "activity history audit log favorites",
            Tool::Appearance => "appearance theme font size scale accent color motion corners language",
            Tool::About => "about help docs threat model update",
        }
    }

    pub fn all() -> &'static [Tool] {
        &[
            Tool::Password,
            Tool::JwtGenerate,
            Tool::JwtDecode,
            Tool::JwtVerify,
            Tool::Encrypt,
            Tool::Hash,
            Tool::Keys,
            Tool::Encoding,
            Tool::Random,
            Tool::Totp,
            Tool::Vault,
            Tool::Checksums,
            Tool::Shredder,
            Tool::JsonTools,
            Tool::TimeCron,
            Tool::RegexTester,
            Tool::DiffViewer,
            Tool::QrCodes,
            Tool::Signatures,
            Tool::Hmac,
            Tool::Certificates,
            Tool::SshKeys,
            Tool::Activity,
            Tool::Appearance,
            Tool::About,
        ]
    }
}

pub struct NavSection {
    pub heading: Option<&'static str>,
    pub tools: &'static [Tool],
}

pub const NAV: &[NavSection] = &[
    NavSection { heading: Some("PASSWORD"), tools: &[Tool::Password] },
    NavSection { heading: Some("JWT"), tools: &[Tool::JwtGenerate, Tool::JwtDecode, Tool::JwtVerify] },
    NavSection { heading: Some("AUTH"), tools: &[Tool::Totp, Tool::Vault] },
    NavSection { heading: Some("CRYPTOGRAPHY"), tools: &[Tool::Encrypt, Tool::Hash, Tool::Keys, Tool::Signatures, Tool::Hmac] },
    NavSection { heading: Some("KEYS & CERTS"), tools: &[Tool::SshKeys, Tool::Certificates] },
    NavSection { heading: Some("FILES"), tools: &[Tool::Checksums, Tool::Shredder] },
    NavSection { heading: Some("DEV"), tools: &[Tool::JsonTools, Tool::TimeCron, Tool::RegexTester, Tool::DiffViewer, Tool::QrCodes] },
    NavSection { heading: Some("UTILITIES"), tools: &[Tool::Encoding, Tool::Random] },
    NavSection { heading: Some("SYSTEM"), tools: &[Tool::Activity, Tool::Appearance] },
    NavSection { heading: Some("ABOUT"), tools: &[Tool::About] },
];
