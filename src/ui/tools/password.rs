use eframe::egui;

use crate::app::state::{AppState, PwTab};
use crate::crypto::password::{
    analyze_password, check_policy, generate_passphrase_with_list, generate_pattern, generate_pin,
    generate_random, pattern_help, WORDLIST,
};
use crate::models::{PasswordStrategy, ToolkitError};
use crate::ui::components::{card, copy_button, danger_button, header, info_box, primary_button, secret_input, warn_box};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Password Generator",
        "CSPRNG-backed passwords, passphrases, PINs, and patterns. Nothing leaves this machine.",
    );
    ui.horizontal(|ui| {
        for tab in [PwTab::Generate, PwTab::Strength, PwTab::Bulk, PwTab::Breach] {
            if ui.selectable_label(state.pw_tab == tab, tab.label()).clicked() {
                state.pw_tab = tab;
            }
        }
    });
    ui.separator();
    match state.pw_tab {
        PwTab::Generate => show_generate(ui, state),
        PwTab::Strength => show_strength(ui, state),
        PwTab::Bulk => show_bulk(ui, state),
        PwTab::Breach => show_breach(ui, state),
    }
}

pub fn show_generate(ui: &mut egui::Ui, state: &mut AppState) {

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
    ui.weak("Example: Copper-River-Window-Planet-7-!");
    ui.separator();
    // Diceware-style: custom wordlist.
    ui.checkbox(&mut state.pw_use_custom_list, "Diceware wordlist (one word per line)");
    if state.pw_use_custom_list {
        if ui.button("Load wordlist file").clicked() {
            if let Some(p) = rfd::FileDialog::new().pick_file() {
                match std::fs::read_to_string(&p) {
                    Ok(t) => {
                        state.pw_custom_list = t;
                        state.set_status(true, "Wordlist loaded.");
                    }
                    Err(e) => state.set_status(false, format!("File could not be read: {e}")),
                }
            }
        }
        ui.add(egui::TextEdit::multiline(&mut state.pw_custom_list).desired_rows(3).desired_width(f32::INFINITY).hint_text("apple\nbanana\n…"));
        let n = word_count(&state.pw_custom_list);
        ui.monospace(format!(
            "Custom list: {n} words → {:.1} bits/word → {:.0} bits for {} words",
            (n.max(2) as f64).log2(),
            (n.max(2) as f64).log2() * state.pw_pass.words as f64,
            state.pw_pass.words
        ));
    } else {
        ui.monospace(format!(
            "Built-in list: {} words → {:.1} bits/word",
            WORDLIST.len(),
            (WORDLIST.len() as f64).log2()
        ));
    }
}

fn word_count(list: &str) -> usize {
    list.lines().map(str::trim).filter(|l| !l.is_empty()).count()
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
        PasswordStrategy::Passphrase => {
            if state.pw_use_custom_list {
                let list: Vec<String> = state
                    .pw_custom_list
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                generate_passphrase_with_list(&state.pw_pass, &list)
            } else {
                let owned: Vec<String> = WORDLIST.iter().map(|s| s.to_string()).collect();
                generate_passphrase_with_list(&state.pw_pass, &owned)
            }
        }
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
            state.log("Password", "password generated");
        }
        Err(e) => state.set_status(false, format!("{e}")),
    }
}

fn human_time(secs: f64) -> String {
    if !secs.is_finite() {
        return "effectively forever".to_string();
    }
    const MIN: f64 = 60.0;
    const H: f64 = 3600.0;
    const D: f64 = 86400.0;
    const Y: f64 = 86400.0 * 365.25;
    if secs < 1.0 {
        "instantly".to_string()
    } else if secs < MIN {
        format!("{secs:.0} seconds")
    } else if secs < H {
        format!("{:.1} minutes", secs / MIN)
    } else if secs < D {
        format!("{:.1} hours", secs / H)
    } else if secs < Y {
        format!("{:.1} days", secs / D)
    } else if secs < Y * 1000.0 {
        format!("{:.1} years", secs / Y)
    } else if secs < Y * 1e9 {
        format!("{:.1} million years", secs / Y / 1e6)
    } else {
        format!("{:.1} billion years", secs / Y / 1e9)
    }
}

fn show_strength(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(380.0);
            card(ui, "Test a password", |ui| {
                ui.add(egui::TextEdit::singleline(&mut state.strength_input).password(true).desired_width(f32::INFINITY));
                ui.weak("Typed here, analyzed locally, never stored or sent.");
            });
        });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            card(ui, "Crack-time simulator", |ui| {
                ui.set_width(ui.available_width());
                if state.strength_input.is_empty() {
                    ui.weak("Type a password on the left.");
                    return;
                }
                let a = analyze_password(&state.strength_input, None);
                ui.monospace(format!("Estimated entropy: {:.1} bits ({})", a.estimated_entropy_bits, a.strength_label));
                // Average guesses = 2^(e-1).
                let guesses = 2f64.powf((a.estimated_entropy_bits - 1.0).max(0.0));
                egui::Grid::new("crack_grid").num_columns(2).striped(true).show(ui, |ui| {
                    ui.label(egui::RichText::new("Attacker").strong().small());
                    ui.label(egui::RichText::new("Average time").strong().small());
                    ui.end_row();
                    for (name, rate) in [
                        ("Online, throttled (10/s)", 10.0),
                        ("Offline, fast hash (1e9/s)", 1e9),
                        ("Offline, Argon2id (1e4/s)", 1e4),
                        ("Nation-state cluster (1e12/s)", 1e12),
                    ] {
                        ui.label(name);
                        ui.monospace(human_time(guesses / rate));
                        ui.end_row();
                    }
                });
            });
            info_box(ui, "Model only: real attackers use dictionaries, leaks, and patterns — not brute force. Length beats complexity.");
        });
    });
}

fn show_bulk(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(340.0);
            card(ui, "Bulk generation", |ui| {
                ui.label("Count (1–500)");
                ui.text_edit_singleline(&mut state.bulk_count);
                ui.label("Length each");
                ui.text_edit_singleline(&mut state.bulk_len);
                ui.weak("Character sets follow the Generate tab's Random toggles.");
                if primary_button(ui, state, "Generate batch").clicked() {
                    do_bulk(state);
                }
                if ui.button("Export .txt").clicked() {
                    if state.bulk_output.is_empty() {
                        state.set_status(false, "Generate a batch first.");
                    } else if let Some(p) = rfd::FileDialog::new().set_file_name("api-keys.txt").save_file() {
                        match std::fs::write(&p, state.bulk_output.as_bytes()) {
                            Ok(()) => state.set_status(true, "Batch exported."),
                            Err(e) => state.set_status(false, format!("File could not be written: {e}")),
                        }
                    }
                }
            });
            warn_box(ui, "Bulk secrets are dev-seeding material. Rotate them, never reuse across environments.");
        });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            card(ui, "Batch output", |ui| {
                ui.set_width(ui.available_width());
                egui::ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut state.bulk_output).code_editor().desired_rows(16).desired_width(f32::INFINITY));
                });
                let o = state.bulk_output.clone();
                copy_button(ui, state, "batch", &o);
            });
        });
    });
}

fn do_bulk(state: &mut AppState) {
    let count: usize = match state.bulk_count.trim().parse() {
        Ok(n) if (1..=500).contains(&n) => n,
        _ => {
            state.set_status(false, "Count must be 1..=500.");
            return;
        }
    };
    let len: usize = match state.bulk_len.trim().parse() {
        Ok(n) if (8..=128).contains(&n) => n,
        _ => {
            state.set_status(false, "Length must be 8..=128.");
            return;
        }
    };
    let cfg = crate::models::RandomPasswordConfig {
        length: len,
        uppercase: state.pw_random.uppercase,
        lowercase: state.pw_random.lowercase,
        numbers: state.pw_random.numbers,
        symbols: state.pw_random.symbols,
        min_uppercase: 0,
        min_lowercase: 0,
        min_numbers: 0,
        min_symbols: 0,
    };
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        match generate_random(&cfg) {
            Ok(p) => out.push(p),
            Err(e) => {
                state.set_status(false, format!("{e}"));
                return;
            }
        }
    }
    state.bulk_output = out.join("\n");
    state.set_status(true, format!("{count} secrets generated."));
    state.log("Password", "bulk batch generated");
}

fn show_breach(ui: &mut egui::Ui, state: &mut AppState) {
    ui.vertical(|ui| {
        ui.set_width(520.0);
        card(ui, "Breach check (opt-in network)", |ui| {
            ui.checkbox(&mut state.breach_opt_in, "Allow one HTTPS call to api.haveibeenpwned.com");
            ui.weak("k-Anonymity: only the first 5 chars of SHA-1(password) leave this machine. The full password never does. Default: off.");
            secret_input(ui, "Password to check", &mut state.breach_password, &mut state.breach_password_visible, false);
            ui.horizontal(|ui| {
                if primary_button(ui, state, "Check breaches").clicked() && !state.breach_busy {
                    if !state.breach_opt_in {
                        state.set_status(false, "Turn on the opt-in checkbox first — no network without consent.");
                    } else if state.breach_password.is_empty() {
                        state.set_status(false, "Enter a password.");
                    } else {
                        state.breach_busy = true;
                        state.breach_result = "Checking…".to_string();
                        // Move an owned copy into the thread; clear the UI field now.
                        let pw = std::mem::take(&mut state.breach_password);
                        let ctx2 = ui.ctx().clone();
                        std::thread::spawn(move || {
                            let msg = match crate::crypto::net::breach_count(&pw) {
                                Ok(0) => "Clean: not found in known breaches.".to_string(),
                                Ok(n) => format!("EXPOSED: seen {n} time(s) in breaches. Change it everywhere."),
                                Err(e) => format!("{e}"),
                            };
                            ctx2.data_mut(|d| d.insert_temp(egui::Id::new("breach_result"), msg));
                            ctx2.request_repaint();
                        });
                    }
                }
                if state.breach_busy {
                    ui.spinner();
                }
            });
            let done: Option<String> = ui.ctx().data_mut(|d| {
                let v = d.get_temp::<String>(egui::Id::new("breach_result"));
                if v.is_some() {
                    d.remove::<String>(egui::Id::new("breach_result"));
                }
                v
            });
            if let Some(msg) = done {
                state.breach_busy = false;
                state.breach_result = msg.clone();
                state.log("Password", "breach check finished");
            }
            if !state.breach_result.is_empty() {
                ui.monospace(&state.breach_result.clone());
            }
        });
        warn_box(ui, "A 'clean' result means 'not in this dataset' — not 'strong'. Keep it long, unique, and managed.");
    });
}
