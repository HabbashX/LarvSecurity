use eframe::egui;

use crate::app::navigation::Tool;
use crate::app::state::AppState;
use crate::app::theme::{ERROR, INFO, SUCCESS, WARNING};

/// Page header: title, description, hairline rule.
pub fn header(ui: &mut egui::Ui, title: &str, desc: &str) {
    ui.heading(title);
    ui.label(egui::RichText::new(desc).small().weak());
    ui.separator();
}

/// Two-column layout helper: left config (narrow), right output (wide).
pub fn two_columns<R>(
    ui: &mut egui::Ui,
    left_width: f32,
    left: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    let out = ui.horizontal_top(|ui| {
        let inner = ui.vertical(|ui| {
            ui.set_width(left_width.min(ui.available_width() * 0.45));
            left(ui)
        });
        inner.inner
    });
    out.inner
}

/// Flat bordered panel with a small-caps title.
pub fn card<R>(
    ui: &mut egui::Ui,
    title: &str,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    egui::Frame::new()
        .fill(ui.style().visuals.code_bg_color)
        .stroke(egui::Stroke::new(
            1.0,
            ui.style().visuals.widgets.noninteractive.bg_stroke.color,
        ))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                egui::RichText::new(title.to_uppercase())
                    .small()
                    .strong()
                    .color(ui.style().visuals.weak_text_color()),
            );
            ui.add_space(6.0);
            add_contents(ui)
        })
        .inner
}

/// Primary action button in the user's accent color.
pub fn primary_button(ui: &mut egui::Ui, state: &AppState, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(text).strong().color(egui::Color32::WHITE))
            .fill(state.accent.color())
            .corner_radius(egui::CornerRadius::same(state.corner))
            .min_size(egui::vec2(0.0, 32.0)),
    )
}

/// Danger/ghost button.
pub fn danger_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(text).color(ERROR))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0, ERROR))
            .corner_radius(egui::CornerRadius::same(8))
            .min_size(egui::vec2(0.0, 32.0)),
    )
}

/// Accent-outline button for secondary actions.
pub fn accent_button(ui: &mut egui::Ui, state: &AppState, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(text).color(state.accent.bright()))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0, state.accent.color()))
            .corner_radius(egui::CornerRadius::same(state.corner)),
    )
}

/// Small status chip, e.g. "OFFLINE".
pub fn chip(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    egui::Frame::new()
        .fill(egui::Color32::TRANSPARENT)
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(egui::CornerRadius::same(32))
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).small().strong().color(color));
        });
}

fn stripe_box(ui: &mut egui::Ui, accent: egui::Color32, text: &str) {
    egui::Frame::new()
        .fill(ui.style().visuals.code_bg_color)
        .stroke(egui::Stroke::new(
            1.0,
            ui.style().visuals.widgets.noninteractive.bg_stroke.color,
        ))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin {
            left: 6,
            right: 10,
            top: 8,
            bottom: 8,
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (bar, _) =
                    ui.allocate_exact_size(egui::vec2(3.0, 26.0), egui::Sense::hover());
                ui.painter()
                    .rect_filled(bar, egui::CornerRadius::same(2), accent);
                ui.label(egui::RichText::new(text).small());
            });
        });
}

pub fn warn_box(ui: &mut egui::Ui, text: &str) {
    stripe_box(ui, WARNING, text);
}

pub fn info_box(ui: &mut egui::Ui, text: &str) {
    stripe_box(ui, INFO, text);
}

pub fn error_box(ui: &mut egui::Ui, text: &str) {
    stripe_box(ui, ERROR, text);
}

pub fn success_box(ui: &mut egui::Ui, text: &str) {
    stripe_box(ui, SUCCESS, text);
}

/// Password-style input with Show toggle. Never logs the value.
pub fn secret_input(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    visible: &mut bool,
    multiline: bool,
) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.toggle_value(visible, "Show");
        });
    });
    if *visible {
        if multiline {
            ui.add(
                egui::TextEdit::multiline(value)
                    .desired_rows(3)
                    .code_editor()
                    .desired_width(f32::INFINITY),
            );
        } else {
            ui.add(
                egui::TextEdit::singleline(value)
                    .password(false)
                    .desired_width(f32::INFINITY),
            );
        }
    } else if multiline {
        ui.add(
            egui::TextEdit::multiline(value)
                .desired_rows(3)
                .password(true)
                .code_editor()
                .desired_width(f32::INFINITY),
        );
    } else {
        ui.add(
            egui::TextEdit::singleline(value)
                .password(true)
                .desired_width(f32::INFINITY),
        );
    }
}

/// Copy button wired to the clipboard helper with timeout notice.
pub fn copy_button(ui: &mut egui::Ui, state: &mut AppState, label: &str, text: &str) {
    if text.is_empty() {
        return;
    }
    if accent_button(ui, state, &format!("Copy {label}")).clicked() {
        match state.clipboard.copy(label, text) {
            Ok(()) => {
                if state.clipboard.auto_clear_enabled {
                    state.set_status(
                        true,
                        format!(
                            "Copied {label}. Clipboard clears in {}s.",
                            state.clipboard.auto_clear_secs
                        ),
                    );
                } else {
                    state.set_status(true, format!("Copied {label}."));
                }
            }
            Err(e) => state.set_status(false, format!("Copy failed: {e}")),
        }
    }
}

/// Monospace output block with optional copy.
pub fn output_block(ui: &mut egui::Ui, state: &mut AppState, label: &str, text: &str) {
    ui.label(egui::RichText::new(label).strong().small());
    egui::Frame::new()
        .fill(ui.style().visuals.extreme_bg_color)
        .stroke(egui::Stroke::new(
            1.0,
            ui.style().visuals.widgets.noninteractive.bg_stroke.color,
        ))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(8.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut text.to_owned())
                            .code_editor()
                            .desired_rows(4)
                            .desired_width(f32::INFINITY)
                            .interactive(false),
                    );
                });
        });
    copy_button(ui, state, label, text);
}

/// Command palette: fuzzy filter over tools.
pub fn show_command_palette(ctx: &egui::Context, state: &mut AppState) {
    egui::Window::new("Search tools")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 60.0))
        .fixed_size(egui::vec2(440.0, 340.0))
        .show(ctx, |ui| {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut state.palette_query)
                    .hint_text("Type to filter (Esc to close)")
                    .desired_width(f32::INFINITY),
            );
            ui.memory_mut(|m| m.request_focus(resp.id));
            ui.separator();
            let q = state.palette_query.to_lowercase();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for tool in Tool::all() {
                    let hay = format!("{} {}", tool.title(), tool.keywords()).to_lowercase();
                    if !q.is_empty() && !hay.contains(&q) {
                        continue;
                    }
                    let selected = state.tool == *tool;
                    if ui.selectable_label(selected, tool.title()).clicked() {
                        state.switch_tool(*tool);
                        state.palette_open = false;
                    }
                }
            });
            if ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
                for tool in Tool::all() {
                    let hay = format!("{} {}", tool.title(), tool.keywords()).to_lowercase();
                    if q.is_empty() || hay.contains(&q) {
                        state.switch_tool(*tool);
                        state.palette_open = false;
                        break;
                    }
                }
            }
        });
}
