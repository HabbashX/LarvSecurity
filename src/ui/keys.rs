use eframe::egui;

use crate::app::state::AppState;
use crate::crypto::keys::{generate_ec, generate_rsa, generate_symmetric_hex, EcCurve};
use crate::ui::components::{accent_button, copy_button, header, info_box, primary_button, warn_box};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Key Generator",
        "CSPRNG-backed keys for AES, ChaCha20, RSA, and elliptic curves. Private keys are sensitive.",
    );

    ui.collapsing("Symmetric keys (AES / ChaCha20)", |ui| {
        egui::ComboBox::from_label("Size")
            .selected_text(format!("{} bytes ({} bits)", state.sym_size, state.sym_size * 8))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut state.sym_size, 16, "16 bytes (128 bits, AES-128)");
                ui.selectable_value(&mut state.sym_size, 32, "32 bytes (256 bits, AES-256 / ChaCha20)");
            });
        if primary_button(ui, state, "Generate symmetric key").clicked() {
            match generate_symmetric_hex(state.sym_size) {
                Ok((h, b)) => {
                    state.sym_hex = h;
                    state.sym_b64 = b;
                    state.set_status(true, "Symmetric key generated.");
                }
                Err(e) => state.set_status(false, format!("{e}")),
            }
        }
        if !state.sym_hex.is_empty() {
            ui.label("Hex:");
            ui.code(&state.sym_hex.clone());
            let h = state.sym_hex.clone();
            copy_button(ui, state, "symmetric key (hex)", &h);
            ui.label("Base64:");
            ui.code(&state.sym_b64.clone());
            let b = state.sym_b64.clone();
            copy_button(ui, state, "symmetric key (base64)", &b);
        }
    });

    ui.collapsing("RSA", |ui| {
        egui::ComboBox::from_label("Key size")
            .selected_text(format!("{} bits", state.rsa_bits))
            .show_ui(ui, |ui| {
                for b in [2048usize, 3072, 4096] {
                    ui.selectable_value(&mut state.rsa_bits, b, format!("{b} bits"));
                }
            });
        ui.weak("4096-bit generation can take several seconds; the UI stays responsive via background thread.");
        if primary_button(ui, state, "Generate RSA keypair").clicked() && !state.rsa_busy {
            state.rsa_busy = true;
            let bits = state.rsa_bits;
            // Generate on a worker thread to keep the GUI responsive.
            let ctx = ui.ctx().clone();
            std::thread::spawn(move || {
                let mut pub_pem = String::new();
                let mut priv_pem = String::new();
                let res = generate_rsa(bits, &mut pub_pem, &mut priv_pem);
                let payload = match res {
                    Ok(()) => (true, String::new(), pub_pem, priv_pem),
                    Err(e) => (false, e.to_string(), String::new(), String::new()),
                };
                ctx.data_mut(|d| {
                    d.insert_temp(egui::Id::new("rsa_result"), payload)
                });
                ctx.request_repaint();
            });
        }
        // Poll for completed background generation.
        // `remove_temp` needs Default, so store an Option wrapper instead.
        let done: Option<(bool, String, String, String)> = ui.ctx().data_mut(|d| {
            let v = d.get_temp::<(bool, String, String, String)>(egui::Id::new("rsa_result"));
            if v.is_some() {
                d.remove::<(bool, String, String, String)>(egui::Id::new("rsa_result"));
            }
            v
        });
        if let Some((ok, err, pub_pem, priv_pem)) = done {
            state.rsa_busy = false;
            if ok {
                state.rsa_pub = pub_pem;
                state.rsa_priv = priv_pem;
                state.set_status(true, "RSA keypair generated.");
            } else {
                state.set_status(false, err);
            }
        }
        if state.rsa_busy {
            ui.spinner();
            ui.weak("Generating…");
        }
        key_pair_view(ui, state, &state.rsa_pub.clone(), &state.rsa_priv.clone(), "RSA");
    });

    ui.collapsing("Elliptic curve (for ECDSA / JWT ES256-ES512)", |ui| {
        egui::ComboBox::from_label("Curve")
            .selected_text(state.ec_curve.label())
            .show_ui(ui, |ui| {
                for c in EcCurve::all() {
                    ui.selectable_value(&mut state.ec_curve, *c, c.label());
                }
            });
        if primary_button(ui, state, "Generate EC keypair").clicked() {
            match generate_ec(state.ec_curve) {
                Ok((pub_pem, priv_pem)) => {
                    state.ec_pub = pub_pem;
                    state.ec_priv = priv_pem;
                    state.set_status(true, "EC keypair generated.");
                }
                Err(e) => state.set_status(false, format!("{e}")),
            }
        }
        key_pair_view(ui, state, &state.ec_pub.clone(), &state.ec_priv.clone(), "EC");
    });

    warn_box(ui, "Private keys are sensitive: never log, paste into untrusted sites, or save without understanding who can read the file.");
    info_box(ui, "Exporting writes sensitive material to disk. The app will always ask where to save and never writes silently.");
    ui.horizontal(|ui| {
        if accent_button(ui, state, "Export RSA public key…").clicked() {
            export_pem(state, &state.rsa_pub.clone(), "rsa_public.pem");
        }
        if accent_button(ui, state, "Export RSA private key…").clicked() {
            export_pem(state, &state.rsa_priv.clone(), "rsa_private.pem");
        }
        if accent_button(ui, state, "Export EC public key…").clicked() {
            export_pem(state, &state.ec_pub.clone(), "ec_public.pem");
        }
        if accent_button(ui, state, "Export EC private key…").clicked() {
            export_pem(state, &state.ec_priv.clone(), "ec_private.pem");
        }
    });
}

fn key_pair_view(ui: &mut egui::Ui, state: &mut AppState, pub_pem: &str, priv_pem: &str, kind: &str) {
    if pub_pem.is_empty() && priv_pem.is_empty() {
        return;
    }
    ui.label("Public key:");
    ui.code(pub_pem);
    copy_button(ui, state, &format!("{kind} public key"), pub_pem);
    ui.label(egui::RichText::new("Private key — SENSITIVE").strong().color(crate::app::theme::ERROR));
    ui.code(priv_pem);
    copy_button(ui, state, &format!("{kind} private key"), priv_pem);
}

fn export_pem(state: &mut AppState, pem: &str, default_name: &str) {
    if pem.trim().is_empty() {
        state.set_status(false, "Nothing to export yet — generate a key first.");
        return;
    }
    let is_private = default_name.contains("private");
    if is_private {
        // Explicit confirmation happens via the save dialog filename; note sensitivity.
        state.set_status(true, "Warning: the exported file contains a PRIVATE key. Protect it.");
    }
    if let Some(path) = rfd::FileDialog::new().set_file_name(default_name).save_file() {
        match std::fs::write(&path, pem.as_bytes()) {
            Ok(()) => state.set_status(true, format!("Exported to {}", path.to_string_lossy())),
            Err(e) => state.set_status(false, format!("File could not be written: {e}")),
        }
    }
}

