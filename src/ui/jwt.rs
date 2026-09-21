use eframe::egui;

use crate::app::state::{AppState, JwtTab};
use crate::crypto::jwt::{decode_token, generate_token, verify_token};
use crate::models::JwtAlgorithm;
use crate::ui::components::{copy_button, danger_button, error_box, header, info_box, primary_button, secret_input, success_box, warn_box};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "JWT Toolkit",
        "Generate (JWS), decode, and verify JSON Web Tokens locally. Signed ≠ encrypted.",
    );

    ui.horizontal(|ui| {
        for (tab, label) in [
            (JwtTab::Generate, "Generate"),
            (JwtTab::Decode, "Decode"),
            (JwtTab::Verify, "Verify"),
        ] {
            if ui
                .selectable_label(state.jwt_tab == tab, label)
                .clicked()
            {
                state.jwt_tab = tab;
            }
        }
    });
    ui.separator();

    warn_box(
        ui,
        "JWT payloads are readable by anyone holding the token. Signing proves integrity/authenticity, not confidentiality. Decoding never verifies.",
    );

    match state.jwt_tab {
        JwtTab::Generate => show_generate(ui, state),
        JwtTab::Decode => show_decode(ui, state),
        JwtTab::Verify => show_verify(ui, state),
    }
}

fn alg_picker(ui: &mut egui::Ui, current: &mut JwtAlgorithm) {
    egui::ComboBox::from_label("Algorithm")
        .selected_text(current.as_str())
        .show_ui(ui, |ui| {
            for a in JwtAlgorithm::all() {
                ui.selectable_value(current, *a, a.as_str());
            }
        });
}

fn show_generate(ui: &mut egui::Ui, state: &mut AppState) {
    alg_picker(ui, &mut state.jwt_alg);
    if state.jwt_alg.is_hmac() {
        info_box(ui, "HMAC: anyone with the secret can sign AND verify. Use ≥ 32 random bytes.");
    } else {
        info_box(ui, "RSA/ECDSA: sign with the PRIVATE key, verify with the PUBLIC key.");
    }

    ui.columns(2, |cols| {
        cols[0].label(egui::RichText::new("Payload (JSON)").strong());
        cols[0].add(
            egui::TextEdit::multiline(&mut state.jwt_payload)
                .code_editor()
                .desired_rows(12)
                .desired_width(f32::INFINITY),
        );
        ui_add_claim_helpers(&mut cols[0], state);

        cols[1].label(egui::RichText::new("Key material").strong());
        secret_input(
            &mut cols[1],
            if state.jwt_alg.is_hmac() { "HMAC secret" } else { "Private key (PEM)" },
            &mut state.jwt_key,
            &mut state.jwt_key_visible,
            !state.jwt_alg.is_hmac(),
        );
        cols[1].add_space(6.0);
        cols[1].horizontal(|ui| {
            if primary_button(ui, state, "Generate token").clicked() {
                match generate_token(state.jwt_alg, &state.jwt_payload, &state.jwt_key) {
                    Ok(t) => {
                        state.jwt_token = t;
                        state.set_status(true, "Token generated.");
                    }
                    Err(e) => state.set_status(false, format!("{e}")),
                }
            }
            if danger_button(ui, "Clear").clicked() {
                state.jwt_token.clear();
            }
        });
        if !state.jwt_token.is_empty() {
            cols[1].label(egui::RichText::new("Token").strong().small());
            cols[1].add(
                egui::TextEdit::multiline(&mut state.jwt_token)
                    .code_editor()
                    .desired_rows(6)
                    .desired_width(f32::INFINITY),
            );
            let tok = state.jwt_token.clone();
            copy_button(&mut cols[1], state, "token", &tok);
        }
    });
}

fn ui_add_claim_helpers(ui: &mut egui::Ui, state: &mut AppState) {
    ui.collapsing("Common claims", |ui| {
        ui.horizontal_wrapped(|ui| {
            for claim in ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"] {
                if ui.small_button(claim).clicked() {
                    insert_claim(&mut state.jwt_payload, claim);
                }
            }
        });
        ui.weak("exp/nbf/iat are numeric dates (seconds since epoch).");
    });
}

fn insert_claim(payload: &mut String, claim: &str) {
    let snippet = match claim {
        "iss" => "\"iss\": \"my-app\"",
        "sub" => "\"sub\": \"12345\"",
        "aud" => "\"aud\": \"my-audience\"",
        "exp" => "\"exp\": 1999999999",
        "nbf" => "\"nbf\": 1720000000",
        "iat" => "\"iat\": 1720000000",
        "jti" => "\"jti\": \"unique-id\"",
        _ => return,
    };
    if payload.trim().is_empty() {
        *payload = format!("{{\n  {snippet}\n}}");
        return;
    }
    // Best-effort: insert before final closing brace.
    if let Some(pos) = payload.rfind('}') {
        let needs_comma = payload[..pos].trim_end().ends_with(|c| c != '{' && c != '\n' && c != ' ');
        let ins = if needs_comma {
            format!(",\n  {snippet}")
        } else {
            format!("\n  {snippet}")
        };
        payload.insert_str(pos, &ins);
    }
}

fn show_decode(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label("Paste a JWT (header.payload.signature):");
    ui.add(
        egui::TextEdit::multiline(&mut state.jwt_decode_input)
            .code_editor()
            .desired_rows(3)
            .desired_width(f32::INFINITY),
    );
    if primary_button(ui, state, "Decode").clicked() {
        // Decoded on demand in the view below; status confirms parse.
        match decode_token(&state.jwt_decode_input) {
            Ok(_) => state.set_status(true, "Token decoded (not verified)."),
            Err(e) => state.set_status(false, format!("{e}")),
        }
    }
    if state.jwt_decode_input.trim().is_empty() {
        return;
    }
    match decode_token(&state.jwt_decode_input) {
        Ok(d) => {
            info_box(
                ui,
                "Decoding does NOT verify authenticity. Anyone can decode; only verification with the right key/algorithm establishes trust.",
            );
            ui.columns(3, |cols| {
                cols[0].label(egui::RichText::new("HEADER").strong().small());
                cols[0].code(&d.header_json);
                cols[1].label(egui::RichText::new("PAYLOAD").strong().small());
                cols[1].code(&d.payload_json);
                cols[2].label(egui::RichText::new("SIGNATURE").strong().small());
                cols[2].code(&d.signature_b64url);
            });
            ui.weak(format!("alg in header: {}", d.algorithm));
        }
        Err(e) => error_box(ui, &e.to_string()),
    }
}

fn show_verify(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label("Verification pins the expected algorithm — the token's alg header is never trusted.");
    alg_picker(ui, &mut state.jwt_verify_alg);
    ui.label("JWT:");
    ui.add(
        egui::TextEdit::multiline(&mut state.jwt_verify_token)
            .code_editor()
            .desired_rows(3)
            .desired_width(f32::INFINITY),
    );
    secret_input(
        ui,
        if state.jwt_verify_alg.is_hmac() { "HMAC secret" } else { "Public key (PEM; private also accepted)" },
        &mut state.jwt_verify_key,
        &mut state.jwt_verify_key_visible,
        !state.jwt_verify_alg.is_hmac(),
    );
    ui.horizontal(|ui| {
        ui.label("iss");
        ui.text_edit_singleline(&mut state.jwt_verify_iss);
        ui.label("aud");
        ui.text_edit_singleline(&mut state.jwt_verify_aud);
    });
    ui.weak("Leave iss/aud empty to skip claim comparison. Signature is always checked.");
    if primary_button(ui, state, "Verify signature").clicked() {
        let iss = if state.jwt_verify_iss.trim().is_empty() {
            None
        } else {
            Some(state.jwt_verify_iss.trim())
        };
        let aud = if state.jwt_verify_aud.trim().is_empty() {
            None
        } else {
            Some(state.jwt_verify_aud.trim())
        };
        // Clone to satisfy borrow checker (iss/aud borrow state).
        let iss_owned = iss.map(|s| s.to_string());
        let aud_owned = aud.map(|s| s.to_string());
        match verify_token(
            &state.jwt_verify_token,
            state.jwt_verify_alg,
            &state.jwt_verify_key,
            iss_owned.as_deref(),
            aud_owned.as_deref(),
        ) {
            Ok(report) => {
                if report.signature_valid {
                    state.set_status(true, "Signature valid.");
                } else {
                    state.set_status(false, "Signature invalid.");
                }
                // Store last report implicitly via status + re-render below.
                state.jwt_token = serde_json::to_string_pretty(&report).unwrap_or_default();
            }
            Err(e) => {
                state.jwt_token.clear();
                state.set_status(false, format!("{e}"));
            }
        }
    }
    if !state.jwt_token.is_empty() {
        if let Ok(report) =
            serde_json::from_str::<crate::models::JwtVerificationReport>(&state.jwt_token)
        {
            ui.add_space(6.0);
            if report.signature_valid {
                success_box(ui, &format!("Signature valid ({})", report.algorithm));
            } else {
                error_box(ui, "Signature invalid. Do not trust this token.");
            }
            egui::Grid::new("verify_grid").num_columns(2).show(ui, |ui| {
                ui.label("Expired");
                ui.monospace(
                    report.expired.map(|b| b.to_string()).unwrap_or_else(|| "n/a".into()),
                );
                ui.end_row();
                ui.label("Not yet valid");
                ui.monospace(
                    report.not_yet_valid.map(|b| b.to_string()).unwrap_or_else(|| "n/a".into()),
                );
                ui.end_row();
            });
            for w in &report.warnings {
                warn_box(ui, w);
            }
            info_box(
                ui,
                "Cryptographic signature verification ≠ claim validation. A valid signature with expired/wrong-audience claims must still be rejected by your application logic.",
            );
        }
    }
}
