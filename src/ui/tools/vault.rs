use eframe::egui;

use crate::app::state::AppState;
use crate::crypto::vault::{open_blob, seal_blob, wipe_entries, VaultEntry};
use crate::ui::components::{card, copy_button, danger_button, header, info_box, primary_button, secret_input, warn_box};
use crate::utils::secure_memory::clear_string;

/// Lock now: wipe decrypted entries + master from memory.
pub fn lock_vault(state: &mut AppState) {
    wipe_entries(&mut state.vault_entries);
    clear_string(&mut state.vault_master);
    clear_string(&mut state.vault_new_secret);
    state.vault_unlocked = false;
    state.vault_lock_at = None;
    state.vault_master_visible = false;
    state.vault_new_secret_visible = false;
    state.log("Vault", "locked");
}

fn arm_lock_timer(state: &mut AppState) {
    let mins: u64 = state.vault_lock_minutes.trim().parse().unwrap_or(15).clamp(1, 480);
    state.vault_lock_at = Some(std::time::Instant::now() + std::time::Duration::from_secs(mins * 60));
}

/// Duress action: lock vault AND clear every transient secret in the app.
pub fn panic_lock(state: &mut AppState) {
    lock_vault(state);
    clear_string(&mut state.jwt_key);
    clear_string(&mut state.jwt_verify_key);
    clear_string(&mut state.enc_password);
    clear_string(&mut state.dec_password);
    clear_string(&mut state.kdf_password);
    clear_string(&mut state.breach_password);
    clear_string(&mut state.hmac_key);
    clear_string(&mut state.sig_priv);
    clear_string(&mut state.ssh_priv);
    clear_string(&mut state.rsa_priv);
    clear_string(&mut state.ec_priv);
    state.totp_probe.clear();
    state.totp_probe_result.clear();
    state.set_status(true, "Panic lock engaged: all secrets cleared.");
    state.log("Vault", "PANIC lock engaged");
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Vault",
        "Master-password vault for logins + secure notes. AES-256-GCM + Argon2id. Auto-locks on a timer.",
    );

    if !state.vault_unlocked {
        ui.vertical(|ui| {
            ui.set_width(420.0);
            card(ui, "Unlock vault", |ui| {
                secret_input(ui, "Master password", &mut state.vault_master, &mut state.vault_master_visible, false);
                ui.horizontal(|ui| {
                    ui.label("Auto-lock after (min)");
                    ui.text_edit_singleline(&mut state.vault_lock_minutes);
                });
                ui.horizontal(|ui| {
                    if primary_button(ui, state, "Unlock").clicked() {
                        unlock(state);
                    }
                    if ui.button("New empty vault").clicked() {
                        new_vault(state);
                    }
                });
                ui.weak("Forgot the master password? There is no recovery — that is the point.");
            });
            warn_box(ui, "The vault lives in memory while unlocked and in files only if you export it. Lock when you walk away.");
        });
        return;
    }

    // Remaining lock countdown.
    if let Some(at) = state.vault_lock_at {
        let left = at.saturating_duration_since(std::time::Instant::now()).as_secs();
        ui.weak(format!("Auto-lock in {:02}:{:02}", left / 60, left % 60));
    }

    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(360.0);
            card(ui, "Add entry", |ui| {
                ui.label("Service");
                ui.text_edit_singleline(&mut state.vault_new_service);
                ui.label("Username");
                ui.text_edit_singleline(&mut state.vault_new_user);
                secret_input(ui, "Secret", &mut state.vault_new_secret, &mut state.vault_new_secret_visible, false);
                ui.label("Notes");
                ui.add(egui::TextEdit::multiline(&mut state.vault_new_notes).desired_rows(2).desired_width(f32::INFINITY));
                if primary_button(ui, state, "Add entry").clicked() {
                    if state.vault_new_service.trim().is_empty() {
                        state.set_status(false, "Service name required.");
                    } else {
                        state.vault_entries.push(VaultEntry {
                            service: state.vault_new_service.trim().to_string(),
                            username: state.vault_new_user.trim().to_string(),
                            secret: std::mem::take(&mut state.vault_new_secret),
                            notes: std::mem::take(&mut state.vault_new_notes),
                        });
                        state.vault_new_service.clear();
                        state.vault_new_user.clear();
                        arm_lock_timer(state);
                        state.log("Vault", "entry added");
                        state.set_status(true, "Entry added.");
                    }
                }
            });
            ui.add_space(6.0);
            card(ui, "Lockdown", |ui| {
                if primary_button(ui, state, "Lock vault").clicked() {
                    lock_vault(state);
                    state.set_status(true, "Vault locked.");
                }
                if danger_button(ui, "PANIC — clear everything").clicked() {
                    panic_lock(state);
                }
            });
        });

        ui.add_space(8.0);

        ui.vertical(|ui| {
            card(ui, "Entries", |ui| {
                ui.set_width(ui.available_width());
                if state.vault_entries.is_empty() {
                    ui.weak("No entries. Add one on the left.");
                }
                let mut del: Option<usize> = None;
                for (i, e) in state.vault_entries.clone().iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.set_width(200.0);
                            ui.label(egui::RichText::new(&e.service).strong());
                            ui.weak(&e.username);
                            if !e.notes.is_empty() {
                                ui.weak(&e.notes);
                            }
                        });
                        ui.code(&e.secret);
                        let s = e.secret.clone();
                        copy_button(ui, state, "secret", &s);
                        if ui.small_button("Delete").clicked() {
                            del = Some(i);
                        }
                    });
                    ui.separator();
                }
                if let Some(i) = del {
                    state.vault_entries.remove(i);
                    arm_lock_timer(state);
                    state.log("Vault", "entry deleted");
                }
            });
            ui.add_space(6.0);
            card(ui, "Save / load vault file", |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Seal to file").clicked() {
                        seal_to_file(state);
                    }
                    if ui.button("Open vault file").clicked() {
                        open_from_file(state);
                    }
                });
                ui.weak("The file holds the Argon2id envelope only. The master password is never stored.");
            });
            info_box(ui, "Exporting writes secrets (encrypted) to disk. Anyone with the file AND your master password owns the vault.");
        });
    });
}

fn unlock(state: &mut AppState) {
    if state.vault_master.is_empty() {
        state.set_status(false, "Enter the master password.");
        return;
    }
    // If file text present, open it; else start empty (set on New).
    if !state.vault_file_text.trim().is_empty() {
        match open_blob(&state.vault_file_text, &state.vault_master) {
            Ok(entries) => {
                state.vault_entries = entries;
                state.vault_unlocked = true;
                arm_lock_timer(state);
                state.log("Vault", "unlocked from file");
                state.set_status(true, "Vault unlocked.");
            }
            Err(e) => state.set_status(false, format!("{e}")),
        }
    } else {
        state.vault_unlocked = true;
        arm_lock_timer(state);
        state.log("Vault", "unlocked (empty session)");
        state.set_status(true, "Vault unlocked (empty session). Load a file or add entries.");
    }
}

fn new_vault(state: &mut AppState) {
    if state.vault_master.is_empty() {
        state.set_status(false, "Enter a master password first — it seals the new vault.");
        return;
    }
    state.vault_entries.clear();
    state.vault_file_text.clear();
    state.vault_unlocked = true;
    arm_lock_timer(state);
    state.log("Vault", "new vault created");
    state.set_status(true, "New vault created. Add entries, then Seal to file.");
}

fn seal_to_file(state: &mut AppState) {
    match seal_blob(&state.vault_entries, &state.vault_master) {
        Ok(env) => {
            state.vault_file_text = env.clone();
            if let Some(p) = rfd::FileDialog::new().set_file_name("vault.larv.json").save_file() {
                match std::fs::write(&p, env.as_bytes()) {
                    Ok(()) => {
                        arm_lock_timer(state);
                        state.log("Vault", "sealed to file");
                        state.set_status(true, "Vault sealed to file.");
                    }
                    Err(e) => state.set_status(false, format!("File could not be written: {e}")),
                }
            }
        }
        Err(e) => state.set_status(false, format!("{e}")),
    }
}

fn open_from_file(state: &mut AppState) {
    let Some(p) = rfd::FileDialog::new().pick_file() else {
        return;
    };
    match std::fs::read_to_string(&p) {
        Ok(text) => {
            state.vault_file_text = text;
            state.log("Vault", "vault file staged");
            state.set_status(true, "Vault file staged. Enter master password and Unlock.");
        }
        Err(e) => state.set_status(false, format!("File could not be read: {e}")),
    }
}
