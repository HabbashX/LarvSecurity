use eframe::egui;

use crate::app::state::AppState;
use crate::crypto::random::{
    random_bytes_base64, random_bytes_hex, random_int_inclusive, random_token_urlsafe,
    random_uuid_v4,
};
use crate::ui::components::{copy_button, header, info_box};
use crate::utils::validation::{parse_i64, parse_usize};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Random Generator",
        "Cryptographically secure randomness (OS CSPRNG) for tokens, salts, and nonces.",
    );
    info_box(ui, "All values come from the operating system's CSPRNG (OsRng). Never use Math.random-style PRNGs for secrets.");

    ui.horizontal(|ui| {
        ui.label("Size (bytes)");
        ui.text_edit_singleline(&mut state.rand_size);
    });
    ui.horizontal_wrapped(|ui| {
        if ui.button("Bytes (hex)").clicked() {
            match parse_usize(&state.rand_size.clone(), "size", 1, 1024 * 256) {
                Ok(n) => match random_bytes_hex(n) {
                    Ok(v) => {
                        state.rand_output = v;
                        state.set_status(true, "Random bytes generated.");
                    }
                    Err(e) => state.set_status(false, format!("{e}")),
                },
                Err(e) => state.set_status(false, e),
            }
        }
        if ui.button("Bytes (Base64)").clicked() {
            match parse_usize(&state.rand_size.clone(), "size", 1, 1024 * 256) {
                Ok(n) => match random_bytes_base64(n) {
                    Ok(v) => {
                        state.rand_output = v;
                        state.set_status(true, "Random bytes generated.");
                    }
                    Err(e) => state.set_status(false, format!("{e}")),
                },
                Err(e) => state.set_status(false, e),
            }
        }
        if ui.button("URL-safe token").clicked() {
            match parse_usize(&state.rand_size.clone(), "size", 1, 1024 * 256) {
                Ok(n) => match random_token_urlsafe(n) {
                    Ok(v) => {
                        state.rand_output = v;
                        state.set_status(true, "Random token generated.");
                    }
                    Err(e) => state.set_status(false, format!("{e}")),
                },
                Err(e) => state.set_status(false, e),
            }
        }
        if ui.button("UUID v4").clicked() {
            state.rand_output = random_uuid_v4();
            state.set_status(true, "UUID generated.");
        }
        if ui.button("Clear").clicked() {
            state.rand_output.clear();
        }
    });

    if !state.rand_output.is_empty() {
        ui.code(&state.rand_output.clone());
        let out = state.rand_output.clone();
        copy_button(ui, state, "random value", &out);
    }

    ui.separator();
    ui.label(egui::RichText::new("Random integer (uniform, rejection-sampled)").strong());
    ui.horizontal(|ui| {
        ui.label("min");
        ui.text_edit_singleline(&mut state.rand_int_min);
        ui.label("max");
        ui.text_edit_singleline(&mut state.rand_int_max);
        if ui.button("Generate int").clicked() {
            let a = parse_i64(&state.rand_int_min.clone(), "min");
            let b = parse_i64(&state.rand_int_max.clone(), "max");
            match (a, b) {
                (Ok(lo), Ok(hi)) => match random_int_inclusive(lo, hi) {
                    Ok(v) => {
                        state.rand_output = v.to_string();
                        state.set_status(true, "Random integer generated.");
                    }
                    Err(e) => state.set_status(false, format!("{e}")),
                },
                (Err(e), _) | (_, Err(e)) => state.set_status(false, e),
            }
        }
    });
}
