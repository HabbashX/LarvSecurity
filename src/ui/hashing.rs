use eframe::egui;

use crate::app::state::AppState;
use crate::crypto::hashing::{hash_bytes, hash_file, hash_password_kdf, HashAlgorithm, KdfAlgorithm};
use crate::ui::components::{copy_button, header, info_box, primary_button, secret_input, warn_box};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Hash Generator",
        "One-way digests for integrity checks — hashing is not encryption.",
    );

    ui.columns(2, |cols| {
        cols[0].label(egui::RichText::new("Input").strong());
        cols[0].label("Text:");
        cols[0].add(
            egui::TextEdit::multiline(&mut state.hash_input)
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        );
        cols[0].horizontal(|ui| {
            ui.label("File");
            ui.text_edit_singleline(&mut state.hash_file_path);
            if ui.button("Browse…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    state.hash_file_path = p.to_string_lossy().into_owned();
                }
            }
        });
        cols[0].weak("If a file path is set, the file is hashed (streamed in 64 KiB chunks); otherwise the text above is hashed.");

        cols[1].label(egui::RichText::new("Digests").strong());
        egui::ScrollArea::vertical().max_height(420.0).show(&mut cols[1], |ui| {
            for alg in HashAlgorithm::all() {
                let digest = if !state.hash_file_path.trim().is_empty() {
                    match hash_file(*alg, state.hash_file_path.trim()) {
                        Ok(h) => h,
                        Err(e) => {
                            ui.weak(format!("{}: {e}", alg.label()));
                            continue;
                        }
                    }
                } else {
                    hash_bytes(*alg, state.hash_input.as_bytes())
                };
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(alg.label()).small().strong());
                    if alg.is_legacy() {
                        ui.label(egui::RichText::new("LEGACY — not for security").small().color(crate::app::theme::WARNING));
                    }
                });
                ui.code(&digest);
                if ui.small_button(format!("Copy {}", alg.label())).clicked() {
                    match state.clipboard.copy(alg.label(), &digest) {
                        Ok(()) => state.set_status(true, format!("Copied {}.", alg.label())),
                        Err(e) => state.set_status(false, format!("Copy failed: {e}")),
                    }
                }
                ui.separator();
            }
        });
    });

    warn_box(ui, "MD5 and SHA-1 are legacy: fine for checksums against old systems, never for password storage or modern authentication.");
    info_box(ui, "Hashing is one-way and is not encryption. Identical inputs produce identical digests (no salt here).");

    ui.separator();
    ui.label(egui::RichText::new("Password hashing (KDF) — for storage, not checksums").strong());
    ui.weak("Encryption ≠ hashing ≠ password hashing. Password hashing must be slow and salted; Argon2id is the default.");
    egui::ComboBox::from_label("KDF")
        .selected_text(state.kdf_alg.label())
        .show_ui(ui, |ui| {
            for a in KdfAlgorithm::all() {
                ui.selectable_value(&mut state.kdf_alg, *a, a.label());
            }
        });
    secret_input(ui, "Password", &mut state.kdf_password, &mut state.kdf_password_visible, false);
    if primary_button(ui, state, "Hash password").clicked() {
        match hash_password_kdf(state.kdf_alg, &state.kdf_password, 600_000) {
            Ok(h) => {
                state.kdf_output = h;
                state.set_status(true, "Password hashed (PHC format).");
            }
            Err(e) => state.set_status(false, format!("{e}")),
        }
    }
    if !state.kdf_output.is_empty() {
        ui.code(&state.kdf_output.clone());
        let out = state.kdf_output.clone();
        copy_button(ui, state, "KDF hash", &out);
    }
}
