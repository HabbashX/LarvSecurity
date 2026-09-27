use eframe::egui;

use crate::app::state::AppState;
use crate::crypto::ssh::{generate_ed25519, generate_rsa_ssh, inspect_openssh_line};
use crate::ui::components::{card, copy_button, header, info_box, primary_button, warn_box};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "SSH Keys",
        "ed25519 + RSA keypairs with OpenSSH public lines, SHA256 fingerprints, and line inspection.",
    );
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(360.0);
            card(ui, "Generate", |ui| {
                egui::ComboBox::from_label("Type")
                    .selected_text(if state.ssh_kind == "ed25519" { "ed25519 (recommended)" } else { "RSA" })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut state.ssh_kind, "ed25519".to_string(), "ed25519 (recommended)");
                        ui.selectable_value(&mut state.ssh_kind, "rsa".to_string(), "RSA");
                    });
                if state.ssh_kind == "rsa" {
                    egui::ComboBox::from_label("RSA size")
                        .selected_text(format!("{} bits", state.ssh_bits))
                        .show_ui(ui, |ui| {
                            for b in [2048usize, 3072, 4096] {
                                ui.selectable_value(&mut state.ssh_bits, b, format!("{b} bits"));
                            }
                        });
                }
                ui.label("Comment (user@host)");
                ui.text_edit_singleline(&mut state.ssh_comment);
                if primary_button(ui, state, "Generate SSH key").clicked() {
                    let res = if state.ssh_kind == "ed25519" {
                        generate_ed25519(&state.ssh_comment)
                    } else {
                        generate_rsa_ssh(state.ssh_bits, &state.ssh_comment)
                    };
                    match res {
                        Ok(k) => {
                            state.ssh_priv = k.private_pem;
                            state.ssh_pub = k.public_openssh;
                            state.ssh_fp = k.fingerprint;
                            state.set_status(true, "SSH key generated.");
                            state.log("SSH", "keypair generated");
                        }
                        Err(e) => state.set_status(false, format!("{e}")),
                    }
                }
                if !state.ssh_fp.is_empty() {
                    ui.monospace(&state.ssh_fp.clone());
                }
            });
            ui.add_space(6.0);
            card(ui, "Inspect public line", |ui| {
                ui.text_edit_singleline(&mut state.ssh_inspect);
                if ui.button("Fingerprint").clicked() {
                    match inspect_openssh_line(&state.ssh_inspect) {
                        Ok((t, f)) => {
                            state.ssh_inspect_out = format!("type: {t}\n{f}");
                            state.set_status(true, "Line parsed.");
                        }
                        Err(e) => state.set_status(false, format!("{e}")),
                    }
                }
                if !state.ssh_inspect_out.is_empty() {
                    ui.monospace(&state.ssh_inspect_out.clone());
                }
            });
        });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            card(ui, "Public (authorized_keys line)", |ui| {
                ui.set_width(ui.available_width());
                if state.ssh_pub.is_empty() {
                    ui.weak("Nothing generated yet.");
                } else {
                    ui.code(&state.ssh_pub.clone());
                    let p = state.ssh_pub.clone();
                    copy_button(ui, state, "public key", &p);
                }
            });
            ui.add_space(6.0);
            card(ui, "Private (PKCS#8 PEM — SENSITIVE)", |ui| {
                if state.ssh_priv.is_empty() {
                    ui.weak("Nothing generated yet.");
                } else {
                    egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                        ui.code(&state.ssh_priv.clone());
                    });
                    let p = state.ssh_priv.clone();
                    copy_button(ui, state, "private key", &p);
                }
            });
            warn_box(ui, "A private key pasted anywhere except your own servers is a compromised key. Prefer ed25519; guard the file with chmod 600.");
            info_box(ui, "Private keys clear automatically when you leave this tool.");
        });
    });
}
