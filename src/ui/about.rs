use eframe::egui;

use crate::app::state::AppState;
use crate::ui::components::{header, info_box, warn_box};

pub fn show(ui: &mut egui::Ui, _state: &mut AppState) {
    header(
        ui,
        "About",
        "Local-first security workstation. Concepts, threat model, and operating assumptions.",
    );

    ui.collapsing("What this app is", |ui| {
        ui.label("A local developer/security utility. Every operation runs on your machine with established Rust crypto crates (AES-GCM, ChaCha20-Poly1305, Argon2, SHA-2/3, BLAKE3, RSA, ECDSA). The app is a safe interface over those implementations — it invents no primitives.");
    });

    ui.collapsing("Concepts", |ui| {
        for (term, def) in [
            ("Password", "A memorized secret. Strength comes from length + randomness + uniqueness, not just character classes."),
            ("Entropy", "Estimated unpredictability in bits. An estimate, never a guarantee; reuse and leaks dominate real risk."),
            ("Hashing", "One-way digest (e.g. SHA-256). Same input → same output. Not encryption; not reversible."),
            ("Password hashing / KDF", "Slow salted hashing for storage (Argon2id default). Encryption ≠ hashing ≠ password hashing."),
            ("Encryption", "Reversible with the right key. This app uses authenticated encryption (AEAD) only."),
            ("Authenticated encryption", "Confidentiality + tamper detection. Modified ciphertext fails decryption."),
            ("KDF", "Key derivation function (Argon2id here): turns a password + salt into a key."),
            ("Nonce", "Number used once: fresh random bytes per encryption. Never reuse with the same key."),
            ("Salt", "Random per-password value making identical passwords hash differently."),
            ("Cryptographic key", "Exact-size random bytes (e.g. 32 for AES-256). A password is not a key until passed through a KDF."),
            ("JWT / JWS", "Signed token: integrity + authenticity, normally NO confidentiality. Verify = check signature with pinned algorithm + key."),
            ("JWE", "Encrypted JWT (not generated here): adds confidentiality. Do not call a signed JWT 'encrypted'."),
            ("Base64", "Encoding for transport, not confidentiality. Anyone can decode it."),
        ] {
            ui.label(egui::RichText::new(term).strong().small());
            ui.label(egui::RichText::new(def).small());
            ui.add_space(4.0);
        }
    });

    ui.collapsing("JWT: signing vs encryption", |ui| {
        ui.label("JWS (what this app produces) proves who signed and that nothing changed — but the payload stays readable. JWE would additionally hide the payload. Never put secrets in a signed-only JWT payload.");
    });

    ui.collapsing("Threat model", |ui| {
        info_box(ui, "Protects against: accidental exposure, weak crypto choices, implementation mistakes, plaintext storage, unsafe randomness.");
        warn_box(ui, "Cannot protect if: the OS is compromised, malware/keyloggers run, you export secrets insecurely, or you share them. No tool is 100% secure, unhackable, or military-grade — beware such claims.");
    });

    ui.collapsing("Security notes", |ui| {
        ui.label("• No telemetry, no network calls. State clears secrets when switching tools.\n• Clipboard auto-clears (configurable in the sidebar).\n• Memory clearing is best-effort: high-level languages, swap, and OS buffers prevent guarantees.\n• Logs never include passwords, keys, secrets, or plaintext.");
    });
}
