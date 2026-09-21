use eframe::egui;

use crate::app::state::AppState;
use crate::app::theme::{apply_theme, install_custom_font, AccentChoice, ThemeMode};
use crate::ui::components::{card, header, info_box};

pub fn show(ctx: &egui::Context, ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Appearance",
        "Type, scale, accent, and motion. Changes apply instantly and stay on this machine.",
    );

    // Snapshot to detect changes.
    let before = (
        state.theme,
        state.accent,
        state.base_size.to_bits(),
        state.mono_ui,
        state.ui_scale.to_bits(),
        state.corner,
        state.motion,
    );

    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(360.0);

            card(ui, "Theme", |ui| {
                ui.label("Color scheme");
                ui.horizontal(|ui| {
                    for m in ThemeMode::all() {
                        if ui.selectable_label(state.theme == *m, m.label()).clicked() {
                            state.theme = *m;
                        }
                    }
                });
                ui.add_space(4.0);
                ui.label("Accent color");
                egui::Grid::new("accent_grid").num_columns(3).show(ui, |ui| {
                    for (i, a) in AccentChoice::all().iter().enumerate() {
                        let selected = state.accent == *a;
                        ui.horizontal(|ui| {
                            let (dot, resp) =
                                ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::click());
                            ui.painter().circle_filled(dot.center(), 9.0, a.color());
                            if selected {
                                ui.painter().circle_stroke(
                                    dot.center(),
                                    11.0,
                                    egui::Stroke::new(1.5, a.bright()),
                                );
                            }
                            if resp.clicked() {
                                state.accent = *a;
                            }
                            if ui.selectable_label(selected, a.label()).clicked() {
                                state.accent = *a;
                            }
                        });
                        if i % 3 == 2 {
                            ui.end_row();
                        }
                    }
                });
            });

            ui.add_space(8.0);
            card(ui, "Motion", |ui| {
                ui.checkbox(&mut state.motion, "Animated backdrop");
                ui.weak("Drifting geometries, aurora washes, dot grid. Turn off to reduce distraction.");
            });
        });

        ui.add_space(8.0);

        ui.vertical(|ui| {
            card(ui, "Typography", |ui| {
                ui.set_width(ui.available_width());
                ui.checkbox(&mut state.mono_ui, "Monospace interface type");
                ui.weak("Uses the monospace face for labels and headings. Code blocks always stay monospace.");
                ui.add(egui::Slider::new(&mut state.base_size, 11.0..=17.0).text("Base font size"));
                ui.horizontal(|ui| {
                    if ui.button("Load custom font file").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Fonts", &["ttf", "otf"])
                            .pick_file()
                        {
                            match std::fs::read(&path) {
                                Ok(bytes) => {
                                    let name = path
                                        .file_stem()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or("Custom")
                                        .to_string();
                                    state.custom_font_name = Some(name);
                                    state.custom_font_bytes = Some(bytes);
                                    state.set_status(true, "Custom font loaded.");
                                }
                                Err(e) => state.set_status(false, format!("Could not read font: {e}")),
                            }
                        }
                    }
                    if state.custom_font_name.is_some() && ui.button("Reset fonts").clicked() {
                        state.custom_font_name = None;
                        state.custom_font_bytes = None;
                        // Reinstall stock fonts.
                        ctx.set_fonts(egui::FontDefinitions::default());
                    }
                });
                if let Some(name) = &state.custom_font_name.clone() {
                    ui.label(format!("Active custom font: {name}"));
                }
            });

            ui.add_space(8.0);
            card(ui, "Layout", |ui| {
                ui.set_width(ui.available_width());
                ui.add(egui::Slider::new(&mut state.ui_scale, 0.8..=1.5).text("Interface scale"));
                ui.weak("Scales the whole UI. Useful on HiDPI displays.");
                ui.add(egui::Slider::new(&mut state.corner, 0..=14).text("Corner radius"));
                ui.weak("Sharp (0) to soft (14) widget corners.");
            });

            ui.add_space(8.0);
            card(ui, "Preview", |ui| {
                ui.set_width(ui.available_width());
                ui.heading("Heading AaBbCc 123");
                ui.label("Body text renders like this. 1234567890");
                ui.monospace("Monospace 0123456789 abcdef");
                ui.horizontal(|ui| {
                    let _ = crate::ui::components::primary_button(ui, state, "Primary");
                    let _ = crate::ui::components::accent_button(ui, state, "Secondary");
                    let _ = crate::ui::components::danger_button(ui, "Danger");
                });
                info_box(ui, "Accent, size, and corners update everywhere the moment you change them.");
            });
        });
    });

    let after = (
        state.theme,
        state.accent,
        state.base_size.to_bits(),
        state.mono_ui,
        state.ui_scale.to_bits(),
        state.corner,
        state.motion,
    );
    if before != after {
        if state.custom_font_bytes.is_some() && state.custom_font_name.is_some() {
            // Reinstall custom font on top of defaults, then restyle.
            let name = state.custom_font_name.clone().unwrap();
            let bytes = state.custom_font_bytes.clone().unwrap();
            install_custom_font(ctx, &name, &bytes);
        }
        ctx.set_pixels_per_point(state.ui_scale);
        apply_theme(
            ctx,
            state.theme,
            state.accent,
            state.base_size,
            state.mono_ui,
            state.corner,
        );
    }
}
