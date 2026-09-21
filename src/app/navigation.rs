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
            Tool::Appearance => "Appearance",
            Tool::About => "About",
        }
    }

    pub fn keywords(self) -> &'static str {
        match self {
            Tool::Password => "password passphrase pin pattern entropy generator",
            Tool::JwtGenerate => "jwt json web token generate sign jws hs256 rs256 es256",
            Tool::JwtDecode => "jwt decode inspect header payload signature base64",
            Tool::JwtVerify => "jwt verify signature exp nbf iss aud",
            Tool::Encrypt => "encrypt decrypt aes gcm chacha argon2 file password key",
            Tool::Hash => "hash sha blake argon pbkdf scrypt kdf file checksum",
            Tool::Keys => "key rsa ec p256 aes chacha generate pem",
            Tool::Encoding => "encoding base64 hex url decode encode",
            Tool::Random => "random bytes uuid token integer csprng",
            Tool::Appearance => "appearance theme font size scale accent color motion corners",
            Tool::About => "about help docs threat model",
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
    NavSection { heading: Some("CRYPTOGRAPHY"), tools: &[Tool::Encrypt, Tool::Hash, Tool::Keys] },
    NavSection { heading: Some("UTILITIES"), tools: &[Tool::Encoding, Tool::Random] },
    NavSection { heading: Some("SETTINGS"), tools: &[Tool::Appearance] },
    NavSection { heading: Some("ABOUT"), tools: &[Tool::About] },
];
