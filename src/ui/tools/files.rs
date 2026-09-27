use eframe::egui;

use crate::app::state::AppState;
use crate::crypto::hashing::HashAlgorithm;
use crate::crypto::manifest::{build_manifest, verify_manifest};
use crate::crypto::shred::ShredPasses;
use crate::ui::components::{card, copy_button, header, info_box, primary_button, warn_box};

pub fn show_checksums(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Checksums",
        "Hash a whole folder into a manifest, verify it later. Streams files in 64 KiB chunks.",
    );
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(360.0);
            card(ui, "Folder", |ui| {
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut state.cs_root);
                    if ui.button("Browse").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            state.cs_root = p.to_string_lossy().into_owned();
                            AppState::touch_recent(&mut state.recents, &state.cs_root.clone());
                        }
                    }
                });
                if !state.recents.is_empty() {
                    ui.weak("Recent:");
                    for r in state.recents.clone().iter().take(5) {
                        let rr = r.clone();
                        if ui.small_button(&rr).clicked() {
                            state.cs_root = rr;
                        }
                    }
                }
                ui.horizontal(|ui| {
                    if primary_button(ui, state, "Build manifest").clicked() {
                        match build_manifest(&state.cs_root, HashAlgorithm::Sha256) {
                            Ok(m) => {
                                state.cs_manifest = m;
                                state.set_status(true, "Manifest built (SHA-256).");
                                state.log("Checksums", "manifest built");
                            }
                            Err(e) => state.set_status(false, format!("{e}")),
                        }
                    }
                    if ui.button("Save manifest").clicked() {
                        if let Some(p) = rfd::FileDialog::new().set_file_name("CHECKSUMS.sha256").save_file() {
                            match std::fs::write(&p, state.cs_manifest.as_bytes()) {
                                Ok(()) => state.set_status(true, "Manifest saved."),
                                Err(e) => state.set_status(false, format!("File could not be written: {e}")),
                            }
                        }
                    }
                    if ui.button("Load manifest").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            match std::fs::read_to_string(&p) {
                                Ok(t) => {
                                    state.cs_manifest = t;
                                    state.set_status(true, "Manifest loaded.");
                                }
                                Err(e) => state.set_status(false, format!("File could not be read: {e}")),
                            }
                        }
                    }
                });
                if primary_button(ui, state, "Verify folder").clicked() {
                    match verify_manifest(&state.cs_root, &state.cs_manifest, HashAlgorithm::Sha256) {
                        Ok(r) => {
                            let mut out = format!("{}\nOK: {}", r.extra_note, r.ok);
                            if !r.missing.is_empty() {
                                out.push_str(&format!("\nMISSING ({}):\n{}", r.missing.len(), r.missing.join("\n")));
                            }
                            if !r.mismatched.is_empty() {
                                out.push_str(&format!("\nMODIFIED ({}):\n{}", r.mismatched.len(), r.mismatched.join("\n")));
                            }
                            state.cs_report = out;
                            let clean = r.missing.is_empty() && r.mismatched.is_empty();
                            state.set_status(clean, if clean { "All files verified." } else { "Differences found — see report." });
                            state.log("Checksums", "folder verified");
                        }
                        Err(e) => state.set_status(false, format!("{e}")),
                    }
                }
            });
        });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            card(ui, "Manifest", |ui| {
                ui.set_width(ui.available_width());
                egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut state.cs_manifest).code_editor().desired_rows(12).desired_width(f32::INFINITY));
                });
                let m = state.cs_manifest.clone();
                copy_button(ui, state, "manifest", &m);
            });
            if !state.cs_report.is_empty() {
                ui.add_space(6.0);
                card(ui, "Report", |ui| {
                    ui.code(&state.cs_report.clone());
                });
            }
            info_box(ui, "A manifest proves integrity only from the moment it was built. Build it on files you trust, store it separately.");
        });
    });
}

pub fn show_shredder(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "File Shredder",
        "Overwrite → rename → delete. For HDDs and USB sticks; SSDs may retain blocks — only destruction is certain there.",
    );
    warn_box(ui, "Shredding is irreversible. The file is gone when this finishes.");
    ui.vertical(|ui| {
        ui.set_width(520.0);
        card(ui, "Target", |ui| {
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut state.sh_path);
                if ui.button("Browse").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        state.sh_path = p.to_string_lossy().into_owned();
                    }
                }
            });
            egui::ComboBox::from_label("Passes")
                .selected_text(state.sh_passes.label())
                .show_ui(ui, |ui| {
                    for p in ShredPasses::all() {
                        ui.selectable_value(&mut state.sh_passes, *p, p.label());
                    }
                });
            if primary_button(ui, state, "Shred file").clicked() {
                let path = state.sh_path.clone();
                let passes = state.sh_passes;
                match crate::crypto::shred::shred_file(&path, passes, &mut |done, total| {
                    state.sh_done = done;
                    state.sh_total = total.max(1);
                }) {
                    Ok(n) => {
                        state.sh_path.clear();
                        state.sh_status = format!("Shredded {n} bytes. File deleted.");
                        state.set_status(true, "File shredded.");
                        state.log("Shredder", "file shredded");
                    }
                    Err(e) => {
                        state.sh_status.clear();
                        state.set_status(false, format!("{e}"));
                    }
                }
            }
            if state.sh_total > 1 || state.sh_done > 0 {
                ui.add(egui::ProgressBar::new(state.sh_done as f32 / state.sh_total as f32).show_percentage());
            }
            if !state.sh_status.is_empty() {
                ui.monospace(&state.sh_status);
            }
        });
    });
}
