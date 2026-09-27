use eframe::egui;

use base64::Engine as _;

use crate::app::state::AppState;
use crate::crypto::sigs::{hmac_bytes, hmac_verify, sign_bytes, verify_bytes, HmacHash, SigScheme};
use crate::ui::components::{card, copy_button, header, info_box, primary_button, secret_input, warn_box};

pub fn show_signatures(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Signatures",
        "Sign and verify bytes with RSA / ECDSA. Sign with PRIVATE, verify with PUBLIC. DER-encoded ECDSA output.",
    );
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(380.0);
            card(ui, "Keys & scheme", |ui| {
                egui::ComboBox::from_label("Scheme")
                    .selected_text(state.sig_scheme.label())
                    .show_ui(ui, |ui| {
                        for s in SigScheme::all() {
                            ui.selectable_value(&mut state.sig_scheme, *s, s.label());
                        }
                    });
                secret_input(ui, "Private key PEM (sign)", &mut state.sig_priv, &mut state.sig_priv_visible, true);
                ui.label("Public key PEM (verify; private also accepted for RSA)");
                ui.add(egui::TextEdit::multiline(&mut state.sig_pub).code_editor().desired_rows(4).desired_width(f32::INFINITY));
            });
        });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            card(ui, "Message", |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label("Text");
                    ui.text_edit_singleline(&mut state.sig_text);
                    ui.label("or file");
                    ui.text_edit_singleline(&mut state.sig_file);
                    if ui.small_button("Browse").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            state.sig_file = p.to_string_lossy().into_owned();
                        }
                    }
                });
                ui.horizontal(|ui| {
                    if primary_button(ui, state, "Sign").clicked() {
                        do_sign(state);
                    }
                    if primary_button(ui, state, "Verify").clicked() {
                        do_verify(state);
                    }
                });
                if !state.sig_out_b64.is_empty() {
                    ui.label("Signature (base64):");
                    ui.code(&state.sig_out_b64.clone());
                    let s = state.sig_out_b64.clone();
                    copy_button(ui, state, "signature", &s);
                }
                if !state.sig_result.is_empty() {
                    ui.monospace(&state.sig_result.clone());
                }
            });
            info_box(ui, "Signatures prove authenticity + integrity, not secrecy. A valid signature on a malicious file still means a malicious file.");
        });
    });
}

fn message_bytes(state: &AppState) -> Result<Vec<u8>, crate::models::ToolkitError> {
    if !state.sig_file.trim().is_empty() {
        crate::crypto::sigs::read_file_chunked(state.sig_file.trim(), 256 * 1024 * 1024)
    } else {
        Ok(state.sig_text.as_bytes().to_vec())
    }
}

fn do_sign(state: &mut AppState) {
    let msg = match message_bytes(state) {
        Ok(m) => m,
        Err(e) => {
            state.set_status(false, format!("{e}"));
            return;
        }
    };
    match sign_bytes(state.sig_scheme, &state.sig_priv, &msg) {
        Ok(sig) => {
            state.sig_out_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);
            state.sig_result.clear();
            state.set_status(true, "Signed.");
            state.log("Signatures", "message signed");
        }
        Err(e) => state.set_status(false, format!("{e}")),
    }
}

fn do_verify(state: &mut AppState) {
    let msg = match message_bytes(state) {
        Ok(m) => m,
        Err(e) => {
            state.set_status(false, format!("{e}"));
            return;
        }
    };
    let sig = match base64::engine::general_purpose::STANDARD.decode(state.sig_out_b64.trim()) {
        Ok(s) => s,
        Err(_) => {
            state.set_status(false, "Signature box must hold base64 from Sign (or paste one).");
            return;
        }
    };
    match verify_bytes(state.sig_scheme, &state.sig_pub, &msg, &sig) {
        Ok(true) => {
            state.sig_result = "VALID signature.".to_string();
            state.set_status(true, "Signature valid.");
            state.log("Signatures", "signature verified (valid)");
        }
        Ok(false) => {
            state.sig_result = "INVALID signature.".to_string();
            state.set_status(false, "Signature invalid.");
            state.log("Signatures", "signature verified (invalid)");
        }
        Err(e) => state.set_status(false, format!("{e}")),
    }
}

pub fn show_hmac(ui: &mut egui::Ui, state: &mut AppState) {
    header(ui, "HMAC", "Keyed message authentication (SHA-2 family). Anyone with the key can both create and check tags.");
    warn_box(ui, "HMAC needs a shared secret key — it is not a digital signature and gives no non-repudiation.");
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(360.0);
            card(ui, "Inputs", |ui| {
                egui::ComboBox::from_label("Hash")
                    .selected_text(state.hmac_hash.label())
                    .show_ui(ui, |ui| {
                        for h in HmacHash::all() {
                            ui.selectable_value(&mut state.hmac_hash, *h, h.label());
                        }
                    });
                secret_input(ui, "Key (UTF-8)", &mut state.hmac_key, &mut state.hmac_key_visible, false);
                ui.label("Message");
                ui.add(egui::TextEdit::multiline(&mut state.hmac_msg).desired_rows(4).desired_width(f32::INFINITY));
                ui.label("Expected tag hex (for Verify)");
                ui.text_edit_singleline(&mut state.hmac_expect);
                ui.horizontal(|ui| {
                    if primary_button(ui, state, "Compute").clicked() {
                        match hmac_bytes(state.hmac_hash, state.hmac_key.as_bytes(), state.hmac_msg.as_bytes()) {
                            Ok(tag) => {
                                state.hmac_out = hex::encode(&tag);
                                state.hmac_result.clear();
                                state.set_status(true, "Tag computed.");
                                state.log("HMAC", "tag computed");
                            }
                            Err(e) => state.set_status(false, format!("{e}")),
                        }
                    }
                    if primary_button(ui, state, "Verify").clicked() {
                        match hex::decode(state.hmac_expect.trim().replace(|c: char| c.is_whitespace(), "")) {
                            Ok(exp) => match hmac_verify(state.hmac_hash, state.hmac_key.as_bytes(), state.hmac_msg.as_bytes(), &exp) {
                                Ok(true) => {
                                    state.hmac_result = "Tag VALID.".to_string();
                                    state.set_status(true, "Tag valid.");
                                }
                                Ok(false) => {
                                    state.hmac_result = "Tag INVALID.".to_string();
                                    state.set_status(false, "Tag invalid.");
                                }
                                Err(e) => state.set_status(false, format!("{e}")),
                            },
                            Err(_) => state.set_status(false, "Expected tag must be hex."),
                        }
                    }
                });
            });
        });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            card(ui, "Tag", |ui| {
                ui.set_width(ui.available_width());
                if state.hmac_out.is_empty() {
                    ui.weak("Nothing computed yet.");
                } else {
                    ui.code(&state.hmac_out.clone());
                    let o = state.hmac_out.clone();
                    copy_button(ui, state, "HMAC tag", &o);
                }
                if !state.hmac_result.is_empty() {
                    ui.monospace(&state.hmac_result.clone());
                }
            });
        });
    });
}
