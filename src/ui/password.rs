use eframe::egui;

use crate::app::state::AppState;
use crate::crypto::password::{
    analyze_password, check_policy, generate_passphrase, generate_pattern, generate_pin,
    generate_random, pattern_help,
};
use crate::models::{PasswordStrategy, ToolkitError};
use crate::ui::components::{card, copy_button, danger_button, header, info_box, primary_button, warn_box};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Password Generator",
        "CSPRNG-backed passwords, passphrases, PINs, and patterns. Nothing leaves this machine.",
    );

    ui.horizontal(|ui| {
        // ---- left: configuration
        ui.vertical(|ui| {
            ui.set_width(340.0);
            card(ui, "Configuration", |ui| {
            egui::ComboBox::from_label("Strategy")
                .selected_text(state.pw_strategy.label())
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut state.pw_strategy,
                        PasswordStrategy::Random,
                        "Random",
                    );
                    ui.selectable_value(
                        &mut state.pw_strategy,
                        PasswordStrategy::Passphrase,
                        "Passphrase",
                    );
                    ui.selectable_value(&mut state.pw_strategy, PasswordStrategy::Pin, "PIN");
                    ui.selectable_value(
                        &mut state.pw_strategy,
                        PasswordStrategy::Pattern,
                        "Pattern",
                    );
                });

            match state.pw_strategy {
                PasswordStrategy::Random => random_config(ui, state),
                PasswordStrategy::Passphrase => passphrase_config(ui, state),
                PasswordStrategy::Pin => pin_config(ui, state),
                PasswordStrategy::Pattern => pattern_config(ui, state),
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if primary_button(ui, state, "Generate  (Ctrl+G)").clicked() {
                    do_generate(state);
                }
                if danger_button(ui, "Clear").clicked() {
                    state.pw_output.clear();
                    state.pw_analysis = None;
                }
            });
            }); // end Configuration card
            ui.add_space(6.0);
            warn_box(
                ui,
                "Strength estimates are approximations. Use a password manager and unique passwords for real accounts.",
            );
        });

        ui.separator();

        // ---- right: output + analysis
        ui.vertical(|ui| {
            card(ui, "Generated password", |ui| {
            if state.pw_output.is_empty() {
                ui.weak("Press Generate.");
            } else {
                egui::Frame::new()
                    .fill(ui.style().visuals.code_bg_color)
                    .stroke(egui::Stroke::new(
                        1.0,
                        ui.style().visuals.widgets.noninteractive.bg_stroke.color,
                    ))
                    .corner_radius(4.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.add(
                            egui::TextEdit::singleline(&mut state.pw_output)
                                .code_editor()
                                .desired_width(f32::INFINITY),
                        );
                    });
                copy_button(ui, state, "password", &state.pw_output.clone());
            }
            }); // end Generated password card
            if let Some(a) = state.pw_analysis.clone() {
                ui.add_space(6.0);
                card(ui, "Analysis", |ui| {
                egui::Grid::new("pw_analysis").num_columns(2).show(ui, |ui| {
                    ui.label("Length");
                    ui.monospace(a.length.to_string());
                    ui.end_row();
                    ui.label("Uppercase / lowercase");
                    ui.monospace(format!("{} / {}", a.has_upper, a.has_lower));
                    ui.end_row();
                    ui.label("Digits / symbols");
                    ui.monospace(format!("{} / {}", a.has_digit, a.has_symbol));
                    ui.end_row();
                    ui.label("Estimated entropy").on_hover_text(
                        "Estimate from character pool size, not a security guarantee.",
                    );
                    ui.monospace(format!("{:.1} bits", a.estimated_entropy_bits));
                    ui.end_row();
                    ui.label("Strength (estimate)");
                    ui.monospace(&a.strength_label);
                    ui.end_row();
                    ui.label("Satisfies policy");
                    ui.monospace(a.satisfies_policy.to_string());
                    ui.end_row();
                });
                }); // end Analysis card
                info_box(
                    ui,
                    "Estimated entropy ≠ actual security. Length, randomness source, and reuse matter more than any single number.",
                );
            }
        });
    });
}

fn random_config(ui: &mut egui::Ui, state: &mut AppState) {
    let c = &mut state.pw_random;
    ui.add(egui::Slider::new(&mut c.length, 8..=128).text("Length"));
    ui.checkbox(&mut c.uppercase, "Uppercase (A–Z)");
    ui.checkbox(&mut c.lowercase, "Lowercase (a–z)");
    ui.checkbox(&mut c.numbers, "Numbers (0–9)");
    ui.checkbox(&mut c.symbols, "Symbols (!@#…)");
    ui.collapsing("Minimum counts", |ui| {
        ui.add(egui::Slider::new(&mut c.min_uppercase, 0..=32).text("Min uppercase"));
        ui.add(egui::Slider::new(&mut c.min_lowercase, 0..=32).text("Min lowercase"));
        ui.add(egui::Slider::new(&mut c.min_numbers, 0..=32).text("Min numbers"));
        ui.add(egui::Slider::new(&mut c.min_symbols, 0..=32).text("Min symbols"));
    });
}

fn passphrase_config(ui: &mut egui::Ui, state: &mut AppState) {
    let c = &mut state.pw_pass;
    ui.add(egui::Slider::new(&mut c.words, 3..=12).text("Words"));
    ui.horizontal(|ui| {
        ui.label("Separator");
        ui.text_edit_singleline(&mut c.separator);
    });
    ui.checkbox(&mut c.capitalize, "Capitalize words");
    ui.checkbox(&mut c.add_number, "Add number");
    ui.checkbox(&mut c.add_symbol, "Add symbol");
    ui.weak(format!("Example: Copper-River-Window-Planet-7-!"));
}

fn pin_config(ui: &mut egui::Ui, state: &mut AppState) {
    egui::ComboBox::from_label("Length")
        .selected_text(state.pw_pin.length.to_string())
        .show_ui(ui, |ui| {
            for n in [4usize, 6, 8, 10, 12] {
                ui.selectable_value(&mut state.pw_pin.length, n, n.to_string());
            }
        });
}

fn pattern_config(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label("Pattern");
    ui.text_edit_singleline(&mut state.pw_pattern);
    ui.weak(pattern_help());
    ui.weak("Literals pass through, e.g. UUU-111 → AbC-482 (with N for digits).");
}

fn do_generate(state: &mut AppState) {
    let res: Result<String, ToolkitError> = match state.pw_strategy {
        PasswordStrategy::Random => generate_random(&state.pw_random),
        PasswordStrategy::Passphrase => generate_passphrase(&state.pw_pass),
        PasswordStrategy::Pin => generate_pin(&state.pw_pin),
        PasswordStrategy::Pattern => generate_pattern(&state.pw_pattern),
    };
    match res {
        Ok(pw) => {
            let mut analysis = analyze_password(&pw, None);
            if state.pw_strategy == PasswordStrategy::Random {
                analysis.satisfies_policy = check_policy(&pw, &state.pw_random);
            }
            state.pw_output = pw;
            state.pw_analysis = Some(analysis);
            state.set_status(true, "Password generated.");
        }
        Err(e) => state.set_status(false, format!("{e}")),
    }
}
