use eframe::egui;

use crate::app::state::{AppState, CryptoTab};
use crate::crypto::encryption::{
    decrypt_with_password, decrypt_with_raw_key, encrypt_with_password, encrypt_with_raw_key,
    parse_raw_key,
};
use crate::models::{ArgonParams, CipherAlgorithm, OutputFormat};
use crate::ui::components::{copy_button, header, info_box, primary_button, secret_input, warn_box};
use crate::utils::secure_memory::clear_bytes;

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Encrypt / Decrypt",
        "Authenticated encryption only (AES-GCM, ChaCha20-Poly1305). Tampered data fails to decrypt.",
    );
    ui.horizontal(|ui| {
        if ui.selectable_label(state.enc_tab == CryptoTab::Text, "Text").clicked() {
            state.enc_tab = CryptoTab::Text;
        }
        if ui.selectable_label(state.enc_tab == CryptoTab::File, "Files").clicked() {
            state.enc_tab = CryptoTab::File;
        }
    });
    ui.separator();
    warn_box(ui, "Never reuse a nonce with the same key — this app always generates a fresh random nonce per encryption.");

    match state.enc_tab {
        CryptoTab::Text => show_text(ui, state),
        CryptoTab::File => show_files(ui, state),
    }
}

fn alg_picker(ui: &mut egui::Ui, alg: &mut CipherAlgorithm) {
    egui::ComboBox::from_label("Algorithm")
        .selected_text(alg.label())
        .show_ui(ui, |ui| {
            for a in CipherAlgorithm::all() {
                ui.selectable_value(alg, *a, a.label());
            }
        });
    ui.weak(format!(
        "Key size: {} bytes · Nonce: {} bytes (auto-generated)",
        alg.key_len(),
        alg.nonce_len()
    ));
}

fn show_text(ui: &mut egui::Ui, state: &mut AppState) {
    ui.columns(2, |cols| {
        // ---------- encrypt column
        cols[0].label(egui::RichText::new("Encrypt").strong());
        alg_picker(&mut cols[0], &mut state.enc_alg);
        cols[0].checkbox(&mut state.enc_mode_password, "Use password (Argon2id) instead of raw key");
        cols[0].label("Plaintext (UTF-8):");
        cols[0].add(
            egui::TextEdit::multiline(&mut state.enc_input)
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        if state.enc_mode_password {
            secret_input(
                &mut cols[0],
                "Password",
                &mut state.enc_password,
                &mut state.enc_password_visible,
                false,
            );
            cols[0].collapsing("Argon2id parameters", |ui| {
                argon_editor(ui, &mut state.enc_argon);
            });
        } else {
            cols[0].label(format!(
                "Raw key (hex or Base64, exactly {} bytes):",
                state.enc_alg.key_len()
            ));
            cols[0].add(
                egui::TextEdit::singleline(&mut state.enc_key_hex).desired_width(f32::INFINITY),
            );
            egui::ComboBox::from_label("Output")
                .selected_text(state.enc_output_format.label())
                .show_ui(&mut cols[0], |ui| {
                    ui.selectable_value(
                        &mut state.enc_output_format,
                        OutputFormat::EnvelopeJson,
                        OutputFormat::EnvelopeJson.label(),
                    );
                    ui.selectable_value(
                        &mut state.enc_output_format,
                        OutputFormat::RawBase64,
                        OutputFormat::RawBase64.label(),
                    );
                });
        }
        cols[0].horizontal(|ui| {
            ui.label("AAD (optional)");
            ui.text_edit_singleline(&mut state.enc_aad);
        });
        if primary_button(&mut cols[0], state, "Encrypt").clicked() {
            do_encrypt(state);
        }
        if !state.enc_output.is_empty() {
            let out = state.enc_output.clone();
            cols[0].code(&out);
            copy_button(&mut cols[0], state, "ciphertext", &out);
        }

        // ---------- decrypt column
        cols[1].label(egui::RichText::new("Decrypt").strong());
        cols[1].label("Encrypted input:");
        cols[1].add(
            egui::TextEdit::multiline(&mut state.dec_input)
                .code_editor()
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        let password_mode = if state.dec_input.trim_start().starts_with('{') {
            true
        } else {
            state.enc_mode_password
        };
        if password_mode {
            secret_input(
                &mut cols[1],
                "Password",
                &mut state.dec_password,
                &mut state.dec_password_visible,
                false,
            );
        } else {
            cols[1].label("Raw key (hex or Base64):");
            cols[1].add(
                egui::TextEdit::singleline(&mut state.dec_key_hex).desired_width(f32::INFINITY),
            );
        }
        cols[1].horizontal(|ui| {
            ui.label("Expected AAD");
            ui.text_edit_singleline(&mut state.dec_aad);
        });
        if primary_button(&mut cols[1], state, "Decrypt").clicked() {
            do_decrypt(state);
        }
        if !state.dec_output.is_empty() {
            cols[1].code(&state.dec_output.clone());
            let out = state.dec_output.clone();
            copy_button(&mut cols[1], state, "plaintext", &out);
        }
    });

    info_box(
        ui,
        "Password ≠ key: passwords go through Argon2id with a random 16-byte salt. Raw keys must be exact-size random bytes. Envelope JSON carries version, algorithm, KDF params, salt, nonce, and ciphertext.",
    );
}

fn argon_editor(ui: &mut egui::Ui, p: &mut ArgonParams) {
    ui.add(egui::Slider::new(&mut p.m_cost_kib, 8192..=262144).text("Memory KiB"));
    ui.add(egui::Slider::new(&mut p.t_cost, 1..=10).text("Iterations"));
    ui.add(egui::Slider::new(&mut p.p_cost, 1..=4).text("Parallelism"));
    ui.weak("Defaults (64 MiB, 3, 1) suit interactive use. File encryption uses the same KDF per file.");
}

fn do_encrypt(state: &mut AppState) {
    let aad = state.enc_aad.as_bytes().to_vec();
    if state.enc_mode_password {
        match encrypt_with_password(
            state.enc_alg,
            state.enc_input.as_bytes(),
            &state.enc_password,
            &aad,
            &state.enc_argon,
        ) {
            Ok(env) => {
                state.enc_output = env;
                state.set_status(true, "Encrypted (password mode)."); state.log("Encrypt", "text encrypted");
            }
            Err(e) => state.set_status(false, format!("{e}")),
        }
    } else {
        // Raw-key mode: parse exact-size key, never truncate/pad.
        let key = match parse_raw_key(&state.enc_key_hex, state.enc_alg) {
            Ok(mut k) => {
                let out = k.clone();
                k.clear();
                out
            }
            Err(e) => {
                state.set_status(false, format!("{e}"));
                return;
            }
        };
        let mut keyc = key.clone();
        match encrypt_with_raw_key(state.enc_alg, state.enc_input.as_bytes(), &key, &aad) {
            Ok(pkg) => {
                let shown = if state.enc_output_format == OutputFormat::RawBase64 {
                    pkg
                } else {
                    // Wrap raw package in a small JSON hint for clarity.
                    format!("{{\n  \"algorithm\": \"{}\",\n  \"mode\": \"raw-key\",\n  \"package_b64\": \"{pkg}\"\n}}", state.enc_alg.label())
                };
                state.enc_output = shown;
                state.set_status(true, "Encrypted (raw-key mode)."); state.log("Encrypt", "text encrypted");
            }
            Err(e) => state.set_status(false, format!("{e}")),
        }
        clear_bytes(&mut keyc);
    }
}

fn do_decrypt(state: &mut AppState) {
    let looks_like_envelope = state.dec_input.trim_start().starts_with('{')
        && state.dec_input.contains("ciphertext_b64");
    if looks_like_envelope {
        let aad = if state.dec_aad.is_empty() { None } else { Some(state.dec_aad.as_bytes()) };
        match decrypt_with_password(&state.dec_input, &state.dec_password, aad) {
            Ok(pt) => {
                state.dec_output = String::from_utf8_lossy(&pt).into_owned();
                state.set_status(true, "Decrypted."); state.log("Encrypt", "text decrypted");
            }
            Err(e) => {
                state.dec_output.clear();
                state.set_status(false, format!("{e}"));
            }
        }
        return;
    }
    // Try envelope first (password mode) with raw JSON wrapper fallback.
    if state.dec_input.trim_start().starts_with('{') {
        // Possibly our raw-key JSON wrapper.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&state.dec_input) {
            if let Some(pkg) = v.get("package_b64").and_then(|x| x.as_str()) {
                let pkg = pkg.to_string();
                let key = match parse_raw_key(&state.dec_key_hex, state.enc_alg) {
                    Ok(k) => k,
                    Err(e) => {
                        state.set_status(false, format!("{e}"));
                        return;
                    }
                };
                match decrypt_with_raw_key(state.enc_alg, &pkg, &key, state.dec_aad.as_bytes()) {
                    Ok(pt) => {
                        state.dec_output = String::from_utf8_lossy(&pt).into_owned();
                        state.set_status(true, "Decrypted."); state.log("Encrypt", "text decrypted");
                    }
                    Err(e) => {
                        state.dec_output.clear();
                        state.set_status(false, format!("{e}"));
                    }
                }
                return;
            }
        }
    }
    // Plain raw Base64 package.
    let key = match parse_raw_key(&state.dec_key_hex, state.enc_alg) {
        Ok(k) => k,
        Err(e) => {
            state.set_status(false, format!("{e}"));
            return;
        }
    };
    match decrypt_with_raw_key(state.enc_alg, &state.dec_input, &key, state.dec_aad.as_bytes()) {
        Ok(pt) => {
            state.dec_output = String::from_utf8_lossy(&pt).into_owned();
            state.set_status(true, "Decrypted."); state.log("Encrypt", "text decrypted");
        }
        Err(e) => {
            state.dec_output.clear();
            state.set_status(false, format!("{e}"));
        }
    }
}

fn show_files(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label(egui::RichText::new("File encryption (streaming-friendly)").strong());
    ui.weak("Files are processed in 64 KiB chunks. Small files use the same AEAD envelope; large files are read incrementally for hashing-style progress. Whole-file AEAD keeps the authentication guarantee (no per-chunk DIY scheme).");
    alg_picker(ui, &mut state.enc_alg);
    ui.horizontal(|ui| {
        ui.label("Input file");
        ui.text_edit_singleline(&mut state.file_input_path);
        if ui.button("Browse…").clicked() {
            if let Some(p) = rfd::FileDialog::new().pick_file() {
                state.file_input_path = p.to_string_lossy().into_owned();
            }
        }
    });
    secret_input(ui, "Password", &mut state.enc_password, &mut state.enc_password_visible, false);
    ui.collapsing("Argon2id parameters", |ui| {
        argon_editor(ui, &mut state.enc_argon);
    });
    ui.horizontal(|ui| {
        if primary_button(ui, state, "Encrypt file…").clicked() {
            encrypt_file(state);
        }
        if primary_button(ui, state, "Decrypt file…").clicked() {
            decrypt_file(state);
        }
    });
    if !state.file_progress.is_empty() {
        ui.monospace(&state.file_progress);
    }
    info_box(ui, "Exported files contain sensitive data. Store them securely and delete plaintext originals only when you intend to.");
}

fn encrypt_file(state: &mut AppState) {
    if state.file_input_path.trim().is_empty() {
        state.set_status(false, "Select an input file first.");
        return;
    }
    if state.enc_password.is_empty() {
        state.set_status(false, "Enter a password.");
        return;
    }
    let data = match read_file_capped(&state.file_input_path, 512 * 1024 * 1024) {
        Ok(d) => d,
        Err(e) => {
            state.set_status(false, e);
            return;
        }
    };
    let alg = state.enc_alg;
    let params = state.enc_argon.clone();
    let pw = state.enc_password.clone();
    match encrypt_with_password(alg, &data, &pw, b"", &params) {
        Ok(env) => {
            let def = format!("{}.enc.json", state.file_input_path);
            let dest = rfd::FileDialog::new()
                .set_file_name(def.rsplit(['/', '\\']).next().unwrap_or("encrypted.enc.json"))
                .save_file();
            match dest {
                Some(p) => match std::fs::write(&p, env.as_bytes()) {
                    Ok(()) => {
                        state.file_progress = format!("Encrypted {} bytes -> {}", data.len(), p.to_string_lossy());
                        state.set_status(true, "File encrypted.");
                    }
                    Err(e) => state.set_status(false, format!("File could not be written: {e}")),
                },
                None => state.set_status(false, "Save cancelled."),
            }
        }
        Err(e) => state.set_status(false, format!("{e}")),
    }
}

fn decrypt_file(state: &mut AppState) {
    if state.file_input_path.trim().is_empty() {
        state.set_status(false, "Select the .enc.json file first.");
        return;
    }
    if state.enc_password.is_empty() {
        state.set_status(false, "Enter the password.");
        return;
    }
    let raw = match read_file_capped(&state.file_input_path, 512 * 1024 * 1024) {
        Ok(d) => d,
        Err(e) => {
            state.set_status(false, e);
            return;
        }
    };
    let text = String::from_utf8_lossy(&raw).into_owned();
    let pw = state.enc_password.clone();
    match decrypt_with_password(&text, &pw, None) {
        Ok(pt) => {
            let dest = rfd::FileDialog::new().save_file();
            match dest {
                Some(p) => match std::fs::write(&p, &pt) {
                    Ok(()) => {
                        state.file_progress = format!("Decrypted {} bytes -> {}", pt.len(), p.to_string_lossy());
                        state.set_status(true, "File decrypted.");
                    }
                    Err(e) => state.set_status(false, format!("File could not be written: {e}")),
                },
                None => state.set_status(false, "Save cancelled."),
            }
        }
        Err(e) => state.set_status(false, format!("{e}")),
    }
}

fn read_file_capped(path: &str, cap: usize) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("File could not be read: {e}"))?;
    if meta.len() as usize > cap {
        return Err(format!("File too large for this build (>{} MiB).", cap / 1024 / 1024));
    }
    // Chunked read (bounded) to avoid one giant read_to_end on adversarial FIFOs.
    let f = std::fs::File::open(path).map_err(|e| format!("File could not be read: {e}"))?;
    let mut reader = std::io::BufReader::new(f);
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    use std::io::Read as _;
    loop {
        let n = reader.read(&mut chunk).map_err(|e| format!("File could not be read: {e}"))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if out.len() > cap {
            return Err("File too large.".into());
        }
    }
    Ok(out)
}

