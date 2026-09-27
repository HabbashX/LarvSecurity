use eframe::egui;

use crate::app::navigation::Tool;
use crate::app::state::{AppState, TotpAccount};
use crate::crypto::totp::{self, TotpHash};
use crate::ui::components::{card, copy_button, header, info_box, primary_button, secret_input, warn_box};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Authenticator",
        "TOTP / HOTP one-time codes (RFC 6238 / 4226). Secrets stay in memory; export via QR only if you choose to.",
    );

    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(340.0);
            card(ui, "Add account", |ui| {
                ui.label("Label");
                ui.text_edit_singleline(&mut state.totp_name);
                secret_input(ui, "Secret (base32)", &mut state.totp_secret, &mut state.totp_secret_visible, false);
                ui.horizontal(|ui| {
                    ui.label("Hash");
                    egui::ComboBox::from_id_salt("totp_hash")
                        .selected_text(state.totp_hash.label())
                        .show_ui(ui, |ui| {
                            for h in TotpHash::all() {
                                ui.selectable_value(&mut state.totp_hash, *h, h.label());
                            }
                        });
                    ui.label("Digits");
                    egui::ComboBox::from_id_salt("totp_digits")
                        .selected_text(state.totp_digits.to_string())
                        .show_ui(ui, |ui| {
                            for d in [6u32, 7, 8] {
                                ui.selectable_value(&mut state.totp_digits, d, d.to_string());
                            }
                        });
                });
                ui.horizontal(|ui| {
                    ui.label("Period (s)");
                    ui.text_edit_singleline(&mut state.totp_step);
                });
                if primary_button(ui, state, "Add account").clicked() {
                    add_account(state);
                }
            });
            ui.add_space(6.0);
            card(ui, "Verify a code", |ui| {
                ui.label("Paste a code to check against all accounts (±1 step).");
                ui.text_edit_singleline(&mut state.totp_probe);
                if ui.button("Check code").clicked() {
                    check_code(state);
                }
                if !state.totp_probe_result.is_empty() {
                    ui.monospace(&state.totp_probe_result.clone());
                }
            });
            warn_box(ui, "Anyone with the secret can generate your codes. Treat TOTP secrets like passwords.");
        });

        ui.add_space(8.0);

        ui.vertical(|ui| {
            card(ui, "Accounts", |ui| {
                ui.set_width(ui.available_width());
                if state.totp_accounts.is_empty() {
                    ui.weak("No accounts yet. Add one on the left.");
                }
                let now = totp::now_unix();
                let mut remove: Option<usize> = None;
                let mut qr_jump: Option<String> = None;
                for (i, acc) in state.totp_accounts.clone().iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.set_width(150.0);
                            ui.label(egui::RichText::new(&acc.name).strong());
                            ui.weak(format!("{} · {} digits · {}s", acc.hash.label(), acc.digits, acc.step));
                        });
                        match totp::decode_secret(&acc.secret_b32)
                            .and_then(|s| totp::totp_at(&s, acc.hash, now, acc.step, acc.digits))
                        {
                            Ok(code) => {
                                ui.monospace(egui::RichText::new(&code).size(22.0).strong());
                                let frac = 1.0 - ((now % acc.step) as f32 / acc.step as f32);
                                ui.add(egui::ProgressBar::new(frac).desired_width(90.0).show_percentage());
                                let c = code.clone();
                                if ui.small_button("Copy").clicked() {
                                    let _ = state.clipboard.copy("TOTP code", &c);
                                    state.set_status(true, "Code copied.");
                                }
                            }
                            Err(e) => {
                                ui.weak(format!("Error: {e}"));
                            }
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Remove").clicked() {
                                remove = Some(i);
                            }
                            if ui.small_button("QR").clicked() {
                                qr_jump = Some(totp::otpauth_uri(
                                    "totp",
                                    &urlencoding::encode(&acc.name),
                                    &acc.secret_b32,
                                    acc.hash,
                                    acc.digits,
                                    acc.step,
                                ));
                            }
                        });
                    });
                    ui.separator();
                }
                if let Some(i) = remove {
                    state.totp_accounts.remove(i);
                    state.log("Authenticator", "account removed");
                }
                if let Some(uri) = qr_jump {
                    state.qr_text = uri;
                    state.qr_unicode.clear();
                    state.qr_svg.clear();
                    state.switch_tool(Tool::QrCodes);
                }
            });
            info_box(ui, "Codes refresh automatically. Time comes from this machine's clock — wrong clock, wrong codes.");
        });
    });
}

fn add_account(state: &mut AppState) {
    if state.totp_name.trim().is_empty() {
        state.set_status(false, "Give the account a label.");
        return;
    }
    let secret_raw = match totp::decode_secret(&state.totp_secret) {
        Ok(s) => s,
        Err(e) => {
            state.set_status(false, format!("{e}"));
            return;
        }
    };
    let step: u64 = match state.totp_step.trim().parse() {
        Ok(n) if n >= 1 && n <= 3600 => n,
        _ => {
            state.set_status(false, "Period must be 1..=3600 seconds.");
            return;
        }
    };
    // Validate by generating once.
    if totp::totp_at(&secret_raw, state.totp_hash, totp::now_unix(), step, state.totp_digits).is_err() {
        state.set_status(false, "Could not use this secret.");
        return;
    }
    state.totp_accounts.push(TotpAccount {
        name: state.totp_name.trim().to_string(),
        secret_b32: totp::encode_secret_base32(&secret_raw),
        hash: state.totp_hash,
        digits: state.totp_digits,
        step,
    });
    state.totp_name.clear();
    state.totp_secret.clear();
    state.log("Authenticator", "account added");
    state.set_status(true, "Account added.");
}

fn check_code(state: &mut AppState) {
    let code = state.totp_probe.trim().to_string();
    let now = totp::now_unix();
    let mut hits = Vec::new();
    for acc in &state.totp_accounts {
        if let Ok(s) = totp::decode_secret(&acc.secret_b32) {
            if totp::verify_totp(&s, acc.hash, now, acc.step, acc.digits, &code, 1).unwrap_or(false) {
                hits.push(acc.name.clone());
            }
        }
    }
    state.totp_probe_result = if hits.is_empty() {
        "No account matches this code.".to_string()
    } else {
        format!("Valid for: {}", hits.join(", "))
    };
    state.totp_probe.clear();
}
